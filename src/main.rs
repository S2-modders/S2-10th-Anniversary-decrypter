use std::cmp::Ordering;

use compression::prelude::{Action, DecodeExt, EncodeExt, LzssCode, LzssDecoder, LzssEncoder};
use crc32fast::hash;
use rayon::prelude::*;
use simple_eyre::eyre::{eyre, Context, Result};
use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes};

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

fn make_random(seed: u32) -> minstd::MINSTD0 {
    let mut seed = seed & 0x7fffffff;
    seed = (5..13 - seed.count_ones() as i32)
        .fold(seed, |seed, i| seed | 1 << (17 + i - 2 * i * (i & 1)));
    seed = (5..seed.count_ones() as i32 - 19)
        .fold(seed, |seed, i| seed & !(1 << (17 + i - 2 * i * (i & 1))));
    minstd::MINSTD0::seed(seed as i32)
}

fn make_key(file_name: &str, game: Game) -> [u8; 16] {
    let key = match game {
        Game::Adk => 0xbd8cc2bd30674bf8b49b1bf9f6822ef4u128.to_be_bytes(),
        Game::Dng => 0xc95946cad9f04f0aa100aab8cbe8db6bu128.to_be_bytes(),
    };
    let file_name = file_name.to_ascii_lowercase();
    let mut rng = make_random(hash(&encoding_rs::WINDOWS_1252.encode(&file_name).0));
    match &file_name[file_name.len() - 4..] {
        ".s2m" | ".sav" => key,
        _ => key.map(|byte| byte ^ rng.next() as u8),
    }
}

fn decompress(iter: &mut impl Iterator<Item = u8>) -> Vec<u8> {
    let mut mode = 0u32;
    let mut totallen = 0;

    let code_iter = std::iter::from_fn(|| {
        if mode & 0x100 == 0 {
            mode = iter.next()? as u32 | 0xff00;
        }
        if mode & 1 != 0 {
            mode >>= 1;
            totallen += 1;
            return Some(LzssCode::Symbol(iter.next()?));
        }
        let curr = iter.next()? as usize;
        let next = iter.next()? as usize;
        let bufferpos = curr | ((next & 0x30) << 4);
        let pos = ((totallen - bufferpos - 16) & 0x3ff).wrapping_sub(1);
        mode >>= 1;
        totallen += 3 + (next & 0xf);
        Some(LzssCode::Reference {
            len: 3 + (next & 0xf),
            pos,
        })
    });

    let d = &mut LzssDecoder::with_dict(0x400, &[b' '; 0x400]);
    code_iter.decode(d).map(Result::unwrap).collect()
}

fn encrypt_decrypt(key: [u8; 16], data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut random = make_random(hash(&key));

    let flavor1: Vec<u8> = (0..(random.next() & 0x7F) + 0x80)
        .map(|_| random.next() as u8)
        .collect();

    let flavor2: Vec<u8> = (0..(random.next() & 0xF) + 0x11)
        .map(|_| random.next() as u8)
        .collect();

    let start = random.next() as usize % data.len();
    let step = (random.next() as usize & 0x1FFF) + 0x2000;
    data.iter()
        .zip(flavor1.into_iter().cycle())
        .map(|(byte1, byte2)| byte1 ^ byte2)
        .enumerate()
        .map(move |(i, val)| {
            if i >= start && (i - start) % step == 0 {
                val ^ flavor2[(key[i % key.len()] as usize ^ i) % flavor2.len()]
            } else {
                val
            }
        })
}

fn decrypt(key: [u8; 16], header: &Header, contents: &[u8]) -> Result<Vec<u8>> {
    let crc = hash(&key);
    let expect = header.name_crc;
    if crc != expect {
        return Err(eyre!("name crc mismatch: {crc:x} != {expect:x}"));
    }
    let mut dec = encrypt_decrypt(key, contents);
    let expect = header.size.try_into().unwrap();
    let res = decompress(&mut dec);
    let len = res.len();
    if len != expect {
        return Err(eyre!("size mismatch: {len} != {expect}"));
    }
    let crc = hash(&res);
    let expect = header.file_crc;
    if crc != expect {
        return Err(eyre!("data crc mismatch: {crc:x} != {expect:x}"));
    }
    Ok(res)
}

fn compress_lzss(u: &mut impl Iterator<Item = u8>) -> Vec<u8> {
    fn comparison(lhs: LzssCode, rhs: LzssCode) -> Ordering {
        match (lhs, rhs) {
            (LzssCode::Reference { len, pos: _ }, LzssCode::Reference { len: rlen, pos: _ }) => {
                (rlen).cmp(&len)
            }
            (LzssCode::Symbol(_), LzssCode::Symbol(_)) => Ordering::Equal,
            (_, LzssCode::Symbol(_)) => Ordering::Greater,
            (LzssCode::Symbol(_), _) => Ordering::Less,
        }
    }

    let encoder = &mut LzssEncoder::with_dict(comparison, 0x400, 18, 3, 0, &[b' '; 0x400]);
    let cmp = u.encode(encoder, Action::Finish).map(Result::unwrap);

    let mut comp = Vec::with_capacity(cmp.size_hint().0 * 2);
    let mut op_idx = 0;
    let mut op_code = 1u8;

    let mut currpos = 0;
    cmp.for_each(|code| {
        if op_code == 1 {
            op_idx = comp.len();
            comp.push(0);
        }
        currpos += match code {
            LzssCode::Symbol(b) => {
                comp[op_idx] |= op_code;
                comp.push(b);
                1
            }
            LzssCode::Reference { len, pos } => {
                let abspos = (currpos - pos - 16 - 1) & 0x3ff;

                comp.push(abspos as u8);
                comp.push((abspos >> 4) as u8 & 0x30 | (len as u8 - 3));
                len
            }
        };
        op_code = op_code.rotate_left(1);
    });
    comp
}

fn encrypt(key: [u8; 16], contents: &mut impl ExactSizeIterator<Item = u8>, game: Game) -> Vec<u8> {
    let comp = compress_lzss(contents);
    let data = encrypt_decrypt(key, &comp).collect::<Vec<u8>>();
    let header = Header {
        magic: Magic::Magic,
        game,
        file_crc: hash(&data),
        name_crc: hash(&key),
        size: contents.len() as u32,
    };
    header.as_bytes().iter().copied().chain(data).collect()
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
                decrypt(key, header, data)
                    .context(format!("Error while decrypting {}", path.display()))?
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
                encrypt(make_key(file_name, game), &mut data.into_iter(), game)
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
                    let res = decrypt(key, header, data)
                        .context(format!("Error occurred in 1. decryption of {display}"))?;

                    let contents = encrypt(key, &mut res.into_iter(), header.game);
                    decrypt(key, header, &contents[20..])
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
