use binrw::{binrw, error::ContextExt, helpers::until_eof, io::BufReader, BinRead, BinWrite};
use compression::prelude::{Action, DecodeExt, EncodeExt, LzssCode, LzssDecoder, LzssEncoder};
use crc32fast::hash;
use rayon::prelude::*;
use simple_eyre::eyre::{Context, Result};
use std::{cmp::Ordering, fs::File, io::Read};

#[binrw]
#[brw(repr = u32)]
#[repr(u32)]
enum Game {
    Dng = u32::from_le_bytes(*b"rc00"),
    Adk = u32::from_le_bytes(*b"sadk"),
}
#[binrw]
#[brw(little, magic = 0x06091812u32)]
#[brw(import(val1:&str) )]
struct CompressedFile {
    game: Game,
    #[bw(calc = hash(data))]
    file_crc: u32,
    // #[bw(ignore, calc = make_key(val1, &game))]
    // key: [u8; 16],
    #[br(assert(hash(&make_key(val1, &game)) == name_crc))]
    #[bw(calc = hash(&make_key(val1, &game)))]
    name_crc: u32,
    #[bw(calc = data.len().try_into().unwrap())]
    size: u32,
    #[br(parse_with = until_eof)]
    #[br(map = |x:Vec<u8>| decompress(&mut encrypt_decrypt(make_key(val1, &game), &x)))]
    #[br(assert(size as usize == data.len()))]
    #[br(assert(file_crc == hash(&data)))]
    #[bw(map = |x:&Vec<u8>| encrypt_decrypt(make_key(val1, &game), &compress_lzss(x)).collect::<Vec<u8>>())]
    data: Vec<u8>,
}

fn make_random(seed: u32) -> minstd::MINSTD0 {
    let mut seed = seed & 0x7fffffff;
    seed = (5..13 - seed.count_ones() as i32)
        .fold(seed, |seed, i| seed | 1 << (17 + i - 2 * i * (i & 1)));
    seed = (5..seed.count_ones() as i32 - 19)
        .fold(seed, |seed, i| seed & !(1 << (17 + i - 2 * i * (i & 1))));
    minstd::MINSTD0::seed(seed as i32)
}

fn make_key(file_name: &str, game: &Game) -> [u8; 16] {
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
        let len = 3 + (next & 0xf);
        let pos = ((totallen - bufferpos - 16) & 0x3ff).wrapping_sub(1);
        mode >>= 1;
        totallen += len;
        Some(LzssCode::Reference { len, pos })
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

fn compress_lzss(u: &[u8]) -> Vec<u8> {
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
    let cmp = u
        .iter()
        .cloned()
        .encode(encoder, Action::Finish)
        .map(Result::unwrap);

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

#[derive(argh::FromArgs)]
/// decrypts and encrypts files in specified directories
struct Settler2Decrypter {
    /// directories or files to decrypting/encrpt
    #[argh(positional)]
    files: Vec<std::path::PathBuf>,
}

fn main() -> Result<()> {
    simple_eyre::install()?;
    argh::from_env::<Settler2Decrypter>()
        .files
        .into_iter()
        .flat_map(walkdir::WalkDir::new)
        .par_bridge()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .try_for_each(|entry| -> Result<()> {
            let mut path = entry.path().to_owned();
            let mut reader = BufReader::new(File::open(entry.path()).unwrap());
            let file_name = path.file_name().unwrap().to_str().unwrap();
            let data = match CompressedFile::read_args(&mut reader, (file_name,)) {
                Ok(header) => {
                    let ext = match header.game {
                        Game::Adk => "adk.".to_owned(),
                        Game::Dng => "dng.".to_owned(),
                    };
                    path.set_extension(ext + path.extension().unwrap().to_str().unwrap());
                    header.data
                }
                Err(e) if !matches!(e, binrw::Error::BadMagic { .. }) => {
                    return Err(e
                        .with_context(format!("Error while decrypting {file_name}"))
                        .into())
                }
                _ => {
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
                    let mut data: Vec<u8> = Vec::new();
                    reader.read_to_end(&mut data).unwrap();
                    let mut cursor = std::io::Cursor::new(Vec::new());
                    CompressedFile { game, data }.write_args(&mut cursor, (file_name,))?;
                    cursor.into_inner()
                }
            };
            std::fs::write(&path, data).context(format!("could not write to {}", path.display()))
        })
}

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
        .map(|entry| -> Result<isize> {
            let mut reader = BufReader::new(File::open(entry.path()).unwrap());
            let file_name = entry.path().file_name().unwrap().to_str().unwrap();
            match CompressedFile::read_args(&mut reader, (file_name,)) {
                Ok(header) => {
                    let mut cursor = std::io::Cursor::new(Vec::new());
                    header.write_args(&mut cursor, (file_name,))?;
                    let inner = cursor.into_inner();
                    let mut cursor = std::io::Cursor::new(inner.as_slice());
                    CompressedFile::read_args(&mut cursor, (file_name,))
                        .context(format!("Error occurred in 2. decryption of {file_name}"))?;
                    Ok(entry.path().metadata().unwrap().len() as isize
                        - cursor.into_inner().len() as isize)
                }
                Err(e) if !matches!(e, binrw::Error::BadMagic { .. }) => Err(e
                    .with_context(format!("error in 1. decryption of {file_name}"))
                    .into()),
                _ => Ok(0),
            }
        })
        .map(Result::unwrap)
        .sum::<isize>();
    println!("saved {saved} bytes!");
}
