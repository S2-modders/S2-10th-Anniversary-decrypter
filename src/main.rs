use rayon::prelude::*;
use simple_eyre::eyre::{eyre, Context, Result};
use zerocopy::{transmute, Immutable, IntoBytes, KnownLayout, TryFromBytes};

#[derive(TryFromBytes, Immutable, IntoBytes)]
#[repr(u32)]
enum Magic {
    Magic = 0x06091812,
}
#[derive(Copy, Clone, TryFromBytes, Immutable, IntoBytes)]
#[repr(u32)]
enum Game {
    Dng = u32::from_le_bytes(*b"rc00"),
    Adk = u32::from_le_bytes(*b"sadk"),
}
#[derive(KnownLayout, TryFromBytes, Immutable, IntoBytes)]
struct Header {
    magic: Magic,
    game: Game,
    file_crc: u32,
    name_crc: u32,
    size: u32,
}

struct Random {
    seed: u32,
}
impl Random {
    fn new(crc: u32) -> Self {
        let mut seed = crc & 0x7fffffff;
        seed = (5..13 - seed.count_ones() as i32)
            .fold(seed, |seed, i| seed | 1 << (17 + i - 2 * i * (i & 1)));
        seed = (5..seed.count_ones() as i32 - 19)
            .fold(seed, |seed, i| seed & !(1 << (17 + i - 2 * i * (i & 1))));
        Random { seed }
    }

    fn next_int(&mut self) -> u32 {
        let mul = (self.seed as u64) * 7u64.pow(5);
        self.seed = (mul as u32 & 0x7fffffff) + (mul >> 31) as u32;
        self.seed
    }
}

fn gen_crc(data: &[u8]) -> u32 {
    const R0: [u32; 256] = transmute!(*include_bytes!("../rnum0.bin"));
    const R1: [u32; 256] = transmute!(*include_bytes!("../rnum1.bin"));
    const R2: [u32; 256] = transmute!(*include_bytes!("../rnum2.bin"));
    const R3: [u32; 256] = transmute!(*include_bytes!("../rnum3.bin"));
    let div = data.chunks_exact(4).fold(u32::MAX, |div, i| {
        let t = (div ^ u32::from_le_bytes(i.try_into().unwrap())).to_le_bytes();
        R0[t[3] as usize] ^ R1[t[2] as usize] ^ R2[t[1] as usize] ^ R3[t[0] as usize]
    });
    let remainder = data.chunks_exact(4).remainder().iter();
    !remainder.fold(div, |div, i| (div >> 8) ^ R0[(i ^ div as u8) as usize])
}

fn decompress(cmp: &[u8], expected_len: usize) -> Vec<u8> {
    let mut dc = Vec::with_capacity(expected_len);
    dc.extend_from_slice(&[b' '; 16]);
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
        Game::Adk => 0xbd8cc2bd30674bf8b49b1bf9f6822ef4u128.to_be_bytes(),
        Game::Dng => 0xc95946cad9f04f0aa100aab8cbe8db6bu128.to_be_bytes(),
    };
    let file_name = file_name.to_ascii_lowercase();
    let mut rng = Random::new(gen_crc(&encoding_rs::WINDOWS_1252.encode(&file_name).0));
    match &file_name[file_name.len() - 4..] {
        ".s2m" | ".sav" => key,
        _ => key.map(|byte| byte ^ rng.next_int() as u8),
    }
}

fn decrypt(key: [u8; 16], header: &Header, contents: &mut [u8]) -> Result<Vec<u8>> {
    let crc = gen_crc(&key);
    let expect = header.name_crc;
    if crc != expect {
        return Err(eyre!("name crc mismatch: {crc} != {expect}"));
    }
    encrypt_decrypt(key, contents);
    let expect = header.size.try_into().unwrap();
    let res = decompress(contents, expect);
    let len = res.len();
    if len != expect {
        return Err(eyre!("size mismatch: {len} != {expect}"));
    }
    let crc = gen_crc(&res);
    let expect = header.file_crc;
    if crc != expect {
        return Err(eyre!("data crc mismatch: {crc} != {expect}"));
    }
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

        let currcomp = u128::from_be_bytes(u[i + 2..i + 18].try_into().unwrap());
        let min = i.saturating_sub(1023) as u16;
        i += u[i.saturating_sub(1023)..i + 17]
            .windows(18)
            .enumerate()
            .filter(|(_, window)| window[..2] == u[i..i + 2])
            .map(|(j, window)| (u128::from_be_bytes(window[2..18].try_into().unwrap()), j))
            .map(|(currcomp2, j)| ((currcomp2 ^ currcomp).leading_zeros() as usize, j as u16))
            .max()
            .map(|(len, offset)| ((len / 8 + 2).min(u.len() - 18 - i), min + offset + 0x3e0))
            .filter(|(len, _)| *len >= 3)
            .map(|(copy_len, copy_offset)| {
                comp.push(copy_offset as u8);
                comp.push((copy_offset >> 4) as u8 & 0x30 | copy_len as u8 - 3);
                copy_len
            })
            .unwrap_or_else(|| {
                comp[op_idx] |= op_code;
                comp.push(u[i]);
                1
            });
        op_code = op_code.rotate_left(1);
    }
    comp
}

fn encrypt(key: [u8; 16], contents: &[u8], game: Game) -> Vec<u8> {
    let mut comp = compress_lzss(contents);
    encrypt_decrypt(key, &mut comp[20..]);
    let data = &contents[16..contents.len() - 18];
    let len = data.len() as u32;
    let crc = gen_crc(&key);
    let header = [Magic::Magic as u32, game as u32, gen_crc(data), crc, len];
    comp.splice(0..20, header.iter().flat_map(|num| num.to_le_bytes()));
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
        .map(|(mut path, mut data)| -> Result<()> {
            let res = if let Ok((header, data)) = Header::try_mut_from_prefix(&mut data) {
                let ext = match header.game {
                    Game::Adk => "adk.",
                    Game::Dng => "dng.",
                };
                let file_name = path.file_name().unwrap().to_str().unwrap();
                let key = make_key(file_name, header.game);
                path.set_extension(ext.to_owned() + path.extension().unwrap().to_str().unwrap());
                decrypt(key, header, data).context(format!(
                    "Error occurred while decrypting {}",
                    path.display()
                ))?
            } else {
                let file_stem = path.file_stem().unwrap().to_str().unwrap();
                let game = match &file_stem[file_stem.len() - 4..] {
                    ".adk" => Game::Adk,
                    ".dng" => Game::Dng,
                    _ => return Ok(()),
                };
                path.set_file_name(
                    file_stem[..file_stem.len() - 3].to_owned()
                        + path.extension().unwrap().to_str().unwrap(),
                );
                let file_name = path.file_name().unwrap().to_str().unwrap();
                data.splice(0..0, [b' '; 16]);
                data.extend_from_slice(&[0; 18]);
                encrypt(make_key(file_name, game), &data, game)
            };
            std::fs::write(&path, &res)
                .context(format!("could not write to {}", path.display()))?;
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
            .map(|(path, mut data)| -> Result<isize> {
                if let Ok((header, data)) = Header::try_mut_from_prefix(&mut data) {
                    let display = path.display();
                    let file_name = path.file_name().unwrap().to_str().unwrap();
                    let key = make_key(file_name, header.game);
                    let mut res = decrypt(key, header, data)
                        .context(format!("Error occurred in 1. decryption of {display}"))?;
                    res.splice(0..0, [0x20; 16]);
                    res.extend_from_slice(&[0; 18]);

                    let mut contents = encrypt(key, &res, header.game);
                    decrypt(key, header, &mut contents[20..])
                        .context(format!("Error occurred in 2. decryption of {display}"))?;
                    return Ok(data.len() as isize - contents.len() as isize);
                }
                Ok(0)
            })
            .map(Result::unwrap)
            .sum::<isize>();
        println!("saved {saved} bytes!");
    }
}
