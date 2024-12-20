use rayon::prelude::*;
use simple_eyre::eyre::{eyre, Context, Report, Result};

macro_rules! error_if {
    ($condition:expr, $error_msg:expr) => {
        if $condition {
            return Err($error_msg);
        }
    };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Game {
    DNG = u32::from_le_bytes(*b"rc00") as isize,
    ADK = u32::from_le_bytes(*b"sadk") as isize,
}
const MAGIC: u32 = 0x06091812;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header {
    game: Game,
    file_crc: u32,
    name_crc: u32,
    size: u32,
}
impl TryFrom<&[u8]> for Header {
    type Error = Report;
    fn try_from(header: &[u8]) -> Result<Self> {
        let len = header.len();
        error_if!(len < 20, eyre!("file too short: {len} < 20"));
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        error_if!(magic != MAGIC, eyre!("not encrypted: {magic} != {MAGIC}"));
        Ok(Header {
            game: match u32::from_le_bytes(header[4..8].try_into().unwrap()) {
                0x6b646173 => Game::ADK,
                0x30306372 => Game::DNG,
                fcc => return Err(eyre!("No matching game header found for fcc {fcc:#x}")),
            },
            file_crc: u32::from_le_bytes(header[8..12].try_into().unwrap()),
            name_crc: u32::from_le_bytes(header[12..16].try_into().unwrap()),
            size: u32::from_le_bytes(header[16..20].try_into().unwrap()),
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

const R0: [u32; 256] = include_bytes_plus::include_bytes!("rnum0.bin" as u32le);
const R1: [u32; 256] = include_bytes_plus::include_bytes!("rnum1.bin" as u32le);
const R2: [u32; 256] = include_bytes_plus::include_bytes!("rnum2.bin" as u32le);
const R3: [u32; 256] = include_bytes_plus::include_bytes!("rnum3.bin" as u32le);
fn gen_crc(data: &[u8]) -> u32 {
    let div = data.chunks_exact(4).fold(u32::MAX, |div, i| {
        let t = (div ^ u32::from_le_bytes(i.try_into().unwrap())).to_le_bytes();
        R0[t[3] as usize] ^ R1[t[2] as usize] ^ R2[t[1] as usize] ^ R3[t[0] as usize]
    });
    !data
        .chunks_exact(4)
        .remainder()
        .iter()
        .fold(div, |div, i| (div >> 8) ^ R0[(i ^ div as u8) as usize])
}

fn decompress(cmp: &[u8], expected_len: usize) -> Vec<u8> {
    let mut dc = Vec::with_capacity(expected_len);
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
    let expect = header.name_crc;
    error_if!(crc != expect, eyre!("name crc mismatch: {crc} != {expect}"));
    encrypt_decrypt(key, contents);
    let expect = header.size.try_into().unwrap();
    let res = decompress(contents, expect);
    let len = res.len();
    error_if!(len != expect, eyre!("size mismatch: {len} != {expect}"));
    let crc = gen_crc(&res);
    let expect = header.file_crc;
    error_if!(crc != expect, eyre!("data crc mismatch: {crc} != {expect}"));
    Ok(res)
}

fn compress_lzss(u: &[u8]) -> Vec<u8> {
    let mut comp = Vec::with_capacity(u.len());
    comp.extend_from_slice(&[0; 20]);
    let mut op_idx = 0;
    let mut op_code = 1u8;

    let mut i = 16;
    while i < u.len() - 18 {
        if op_code == 1 {
            op_idx = comp.len();
            comp.push(0);
        }

        let filter = u16::from_ne_bytes(u[i..i + 2].try_into().unwrap());
        let currcomp = u128::from_be_bytes(u[i + 2..i + 18].try_into().unwrap());
        i += match (i.saturating_sub(1023)..i)
            .rev()
            .filter(|j| u16::from_ne_bytes(u[*j..*j + 2].try_into().unwrap()) == filter)
            .map(|j| (u128::from_be_bytes(u[j + 2..j + 18].try_into().unwrap()), j))
            .map(|(currcomp2, j)| ((currcomp2 ^ currcomp).leading_zeros() as usize, j))
            .max()
            .map(|(len, offset)| ((len / 8 + 2).min(u.len() - 18 - i), offset + 0x3f0 - 16))
            .filter(|(len, _)| *len >= 3)
        {
            Some((copy_len, copy_offset)) => {
                comp.push(copy_offset as u8);
                comp.push((copy_offset >> 4) as u8 & 0x30 | copy_len as u8 - 3);
                copy_len
            }
            None => {
                comp[op_idx] |= op_code;
                comp.push(u[i]);
                1
            }
        };
        op_code = op_code.rotate_left(1);
    }
    comp
}

fn encrypt(key: [u8; 16], contents: &[u8], game: Game) -> Vec<u8> {
    let mut comp = compress_lzss(contents);
    encrypt_decrypt(key, &mut comp[20..]);
    let file_crc = gen_crc(&contents[16..contents.len() - 18]);
    let len = contents.len() as u32 - 16 - 18;
    comp.splice(
        0..20,
        [0x06091812, game as u32, file_crc, gen_crc(&key), len]
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
                file.1.splice(0..0, [0x20; 16]);
                file.1.extend_from_slice(&[0; 18]);
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
                    let mut res = decrypt(key, header, &mut file.1[20..])
                        .wrap_err(format!("Error occurred in 1. decryption of {path}"))?;
                    res.splice(0..0, [0x20; 16]);
                    res.extend_from_slice(&[0; 18]);

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
