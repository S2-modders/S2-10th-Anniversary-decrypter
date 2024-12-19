use std::cmp::max;

use rayon::prelude::*;
use simple_eyre::eyre::{eyre, Context, Report, Result};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Game {
    DNG = u32::from_le_bytes(*b"rc00") as isize,
    ADK = u32::from_le_bytes(*b"sadk") as isize,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header {
    game: Game,
    file_crc: u32,
    name_crc: u32,
    size: u32,
}
impl TryFrom<&[u8]> for Header {
    type Error = Report;
    fn try_from(vec: &[u8]) -> Result<Self> {
        let len = vec.len();
        if len < 20 {
            return Err(eyre!("File too short to have a proper header: {len} < 20"));
        }
        let magic = u32::from_le_bytes(vec[0..4].try_into().unwrap());
        if magic != 0x06091812 {
            return Err(eyre!("Not an encrypted file ({magic:#x} != 0x6091812)"));
        }
        Ok(Header {
            game: match u32::from_le_bytes(vec[4..8].try_into().unwrap()) {
                0x6b646173 => Game::ADK,
                0x30306372 => Game::DNG,
                fcc => return Err(eyre!("No matching game header found for fcc {fcc:#x}")),
            },
            file_crc: u32::from_le_bytes(vec[8..12].try_into().unwrap()),
            name_crc: u32::from_le_bytes(vec[12..16].try_into().unwrap()),
            size: u32::from_le_bytes(vec[16..20].try_into().unwrap()),
        })
    }
}

struct Random {
    seed: u32,
}
impl Random {
    fn new(crc: u32) -> Self {
        let mut seed = crc & 0x7fffffff;
        for i in 5..13 - seed.count_ones() as i32 {
            seed |= 1 << (17 + i - 2 * i * (i & 1));
        }
        for i in 5..seed.count_ones() as i32 - 19 {
            seed &= !(1 << (17 + i - 2 * i * (i & 1)));
        }
        Random { seed }
    }

    fn next_int(&mut self) -> u32 {
        let mul = (self.seed as u64) * 7u64.pow(5);
        self.seed = (mul as u32 & 0x7fffffff) + (mul >> 31) as u32;
        self.seed
    }
}

const RNUM0: [u32; 256] = include_bytes_plus::include_bytes!("rnum0.bin" as u32);
const RNUM1: [u32; 256] = include_bytes_plus::include_bytes!("rnum1.bin" as u32);
const RNUM2: [u32; 256] = include_bytes_plus::include_bytes!("rnum2.bin" as u32);
const RNUM3: [u32; 256] = include_bytes_plus::include_bytes!("rnum3.bin" as u32);
fn gen_crc(data: &[u8]) -> u32 {
    let mut div = 0xffffffffu32;
    for i in (0..data.len() & !3).step_by(4) {
        let tmp = div.to_le_bytes();
        div = RNUM0[(tmp[3] ^ data[i + 3]) as usize]
            ^ RNUM1[(tmp[2] ^ data[i + 2]) as usize]
            ^ RNUM2[(tmp[1] ^ data[i + 1]) as usize]
            ^ RNUM3[(tmp[0] ^ data[i]) as usize];
    }
    for i in data.len() & !3..data.len() {
        div = (div >> 8) ^ RNUM0[(data[i] ^ div as u8) as usize];
    }
    !div
}

fn decompress(cmp: &[u8]) -> Vec<u8> {
    let mut dc = Vec::with_capacity(cmp.len() * 9 / 8);
    dc.extend_from_slice(&[0x20; 16]);
    let mut mode = 0;
    let mut iter = cmp.iter();
    while let Some(&curr) = iter.next() {
        if mode & 0x100 == 0 {
            mode = curr as u32 | 0xff00;
        } else if mode & 1 != 0 {
            dc.push(curr);
            mode >>= 1;
        } else if let Some(&next) = iter.next() {
            let num = curr as usize + ((next as usize & 0x30) << 4);
            let c = dc.len() - (dc.len() - num - 32 & 0x3ff);
            (c..c + 3 + (next as usize & 0xf)).for_each(|i| dc.push(dc[i]));
            mode >>= 1;
        }
    }
    dc[16..].to_vec()
}

fn encrypt_decrypt(key: [u8; 16], data: &mut [u8]) {
    let mut random = Random::new(gen_crc(&key));

    let flavor1: Vec<u8> = (0..(random.next_int() & 0x7F) + 0x80)
        .map(|_| random.next_int() as u8)
        .collect();
    data.iter_mut()
        .zip(flavor1.iter().cycle())
        .for_each(|(byte1, byte2)| *byte1 ^= byte2);

    let flavor2: Vec<u8> = (0..(random.next_int() & 0xF) + 0x11)
        .map(|_| random.next_int() as u8)
        .collect();
    for i in (random.next_int() as usize % data.len()..data.len())
        .step_by((random.next_int() as usize & 0x1FFF) + 0x2000)
    {
        data[i] ^= flavor2[(key[i % key.len()] as usize ^ i) % flavor2.len()];
    }
}

fn make_key(file_name: &str, game: Game) -> [u8; 16] {
    let key = match game {
        Game::ADK => 0xbd8cc2bd30674bf8b49b1bf9f6822ef4u128.to_be_bytes(),
        Game::DNG => 0xc95946cad9f04f0aa100aab8cbe8db6bu128.to_be_bytes(),
    };
    let file_name = file_name.to_ascii_lowercase();
    let mut rng = Random::new(gen_crc(&encoding_rs::WINDOWS_1252.encode(&file_name).0));
    match &file_name[file_name.len() - 4..] {
        ".s2m" | ".sav" => return key,
        _ => key.map(|byte| byte ^ rng.next_int() as u8),
    }
}

fn decrypt(key: [u8; 16], header: Header, contents: &mut [u8]) -> Result<Vec<u8>> {
    let crc = gen_crc(&key);
    let expected = header.name_crc;
    if crc != expected {
        return Err(eyre!("file name crc mismatch: {crc:#x} != {expected:#x}"));
    }
    encrypt_decrypt(key, contents);
    let res = decompress(contents);
    let expected_len = header.size.try_into().unwrap();
    let len = res.len();
    if len != expected_len {
        return Err(eyre!("file size mismatch: {len} != {expected_len}"));
    }
    let file_crc = gen_crc(&res);
    let expected = header.file_crc;
    if file_crc != expected {
        return Err(eyre!("file crc mismatch: {file_crc:#x} != {expected:#x}"));
    }
    Ok(res)
}

fn search(idx: usize, uncomp: &[u8]) -> (u8, u16) {
    if idx + 17 >= uncomp.len() {
        return (0, 0);
    }
    let currcomp = u128::from_be_bytes(uncomp[idx + 2..idx + 18].try_into().unwrap());
    let mut copy_len = 0;
    let mut copy_offset = 0;
    for c_idx in (idx.saturating_sub(1023)..idx).rev() {
        if uncomp[idx] == uncomp[c_idx] && uncomp[idx + 1] == uncomp[c_idx + 1] {
            let currcomp2 = u128::from_be_bytes(uncomp[c_idx + 2..c_idx + 18].try_into().unwrap());
            let curr_copy_len = (currcomp2 ^ currcomp).leading_zeros() as u8 / 8 + 2;
            if copy_len < curr_copy_len {
                copy_len = curr_copy_len;
                copy_offset = c_idx as u16 & 0x3ff;
                if curr_copy_len == 18 {
                    break;
                }
            }
        }
    }
    (copy_len, copy_offset)
}

fn compress_lzss(uncomp: &[u8]) -> Vec<u8> {
    let mut comp = Vec::with_capacity(uncomp.len());
    let mut op_idx = 0;
    let mut op_code = 0;
    let mut consume = 0;

    for i in 0..uncomp.len() {
        let (copy_len, copy_offset) = search(i, uncomp);
        if consume == 0 {
            op_code <<= 1;
            if op_code == 0 {
                op_idx = comp.len();
                comp.push(0);
                op_code = 1;
            }

            if copy_len < 3 {
                consume = 1;
                comp[op_idx] |= op_code;
                comp.push(uncomp[i]);
            } else {
                comp.push((copy_offset + 0x3f0) as u8);
                comp.push(((copy_offset + 0x3f0) >> 4) as u8 & 0xf0 | copy_len - 3);
                consume = copy_len;
            }
        }
        consume -= 1;
    }
    comp
}

fn encrypt(key: [u8; 16], contents: &[u8], game: Game) -> Vec<u8> {
    let mut comp = compress_lzss(contents);
    encrypt_decrypt(key, &mut comp);
    comp.splice(
        0..0,
        [
            0x06091812,
            game as u32,
            gen_crc(contents),
            gen_crc(&key),
            contents.len() as u32,
        ]
        .iter()
        .flat_map(|num| num.to_le_bytes()),
    );
    comp
}

fn main() -> Result<()> {
    simple_eyre::install()?;
    std::env::args()
        .collect::<Vec<String>>()
        .into_iter()
        .skip(1)
        .flat_map(walkdir::WalkDir::new)
        .par_bridge()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .map(|file| (file.clone(), std::fs::read(file).unwrap()))
        .map(|mut file| -> Result<()> {
            let res = if let Ok(header) = Header::try_from(file.1.as_slice()) {
                let ext = match header.game {
                    Game::ADK => "adk.",
                    Game::DNG => "dng.",
                };
                let file_name = file.0.file_name().unwrap().to_str().unwrap();
                let key = make_key(file_name, header.game);
                file.0
                    .set_extension(ext.to_owned() + file.0.extension().unwrap().to_str().unwrap());
                decrypt(key, header, &mut file.1[20..]).context(format!(
                    "Error occurred while decrypting {}",
                    file.0.display()
                ))?
            } else {
                let file_stem = file.0.file_stem().unwrap().to_str().unwrap();
                let game = match &file_stem[file_stem.len() - 4..] {
                    ".adk" => Game::ADK,
                    ".dng" => Game::DNG,
                    _ => return Ok(()),
                };
                file.0.set_file_name(
                    file_stem[..file_stem.len() - 3].to_owned()
                        + file.0.extension().unwrap().to_str().unwrap(),
                );
                let file_name = file.0.file_name().unwrap().to_str().unwrap();
                encrypt(make_key(file_name, game), &file.1, game)
            };
            std::fs::write(&file.0, &res)
                .wrap_err(format!("could not write to {}", file.0.display()))?;
            Ok(())
        })
        .find_any(Result::is_err)
        .map_or(Ok(()), |report| report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn is_valid() {
        let saved = std::env::args()
            .collect::<Vec<String>>()
            .into_iter()
            .skip(1)
            .flat_map(walkdir::WalkDir::new)
            .par_bridge()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.path().to_path_buf())
            .map(|file| (file.clone(), std::fs::read(file).unwrap()))
            .map(|mut file| -> Result<isize> {
                if let Ok(header) = Header::try_from(file.1.as_slice()) {
                    let path = file.0.display();
                    let file_name = file.0.file_name().unwrap().to_str().unwrap();
                    let key = make_key(file_name, header.game);
                    let res = decrypt(key, header, &mut file.1[20..])
                        .wrap_err(format!("Error occurred in 1. decryption of {path}"))?;
                    let mut contents = encrypt(key, &res, header.game);
                    assert_eq!(
                        header,
                        Header::try_from(contents.as_slice()).wrap_err(format!(
                            "Error occurred while constructing 2. header of {path}"
                        ))?
                    );
                    decrypt(key, header, &mut contents[20..])
                        .wrap_err(format!("Error occurred in 2. decryption of {path}"))?;
                    return Ok(file.1.len() as isize - contents.len() as isize);
                }
                Ok(0)
            })
            .map(Result::unwrap)
            .sum::<isize>();
        println!("saved {saved} bytes!");
    }
}
