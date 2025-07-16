use binrw::{binrw, helpers::until_eof, BinRead, BinWrite};
use compression::prelude::{Action, DecodeExt, EncodeExt, LzssCode, LzssDecoder, LzssEncoder};
use crc32fast::hash;
use simple_eyre::eyre::{eyre, Result};

#[binrw]
#[brw(repr = u32)]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Game {
    Dng = u32::from_le_bytes(*b"rc00"),
    Adk = u32::from_le_bytes(*b"sadk"),
}

#[binrw]
#[brw(little, magic = 0x06091812u32, import(file_name: &str))]
pub struct DecompressedFile {
    pub game: Game,
    #[bw(calc = hash(data))]
    file_crc: u32,
    #[br(assert(hash(&make_key(file_name, &game)) == name_crc))]
    #[bw(calc = hash(&make_key(file_name, game)))]
    name_crc: u32,
    #[bw(calc = data.len().try_into().unwrap())]
    size: u32,
    #[br(parse_with = until_eof, map = |x:Vec<u8>| decompress(&mut encrypt_decrypt(make_key(file_name, &game), &x)))]
    #[br(assert(size as usize == data.len()), assert(file_crc == hash(&data)))]
    #[bw(map = |x| encrypt_decrypt(make_key(file_name, game), &compress(x)).collect::<Vec<u8>>())]
    pub data: Vec<u8>,
}

fn rng(seed: u32) -> minstd::MINSTD0 {
    let mut seed = seed & 0x7fffffff;
    seed = (5..13 - seed.count_ones() as i32)
        .fold(seed, |seed, i| seed | 1 << (17 + i - 2 * i * (i & 1)));
    seed = (5..seed.count_ones() as i32 - 19)
        .fold(seed, |seed, i| seed & !(1 << (17 + i - 2 * i * (i & 1))));
    minstd::MINSTD0::seed(seed as i32)
}

fn make_key(file: &str, game: &Game) -> [u8; 16] {
    let key = match game {
        Game::Adk => 0xbd8cc2bd30674bf8b49b1bf9f6822ef4u128.to_be_bytes(),
        Game::Dng => 0xc95946cad9f04f0aa100aab8cbe8db6bu128.to_be_bytes(),
    };
    let file = file.to_ascii_lowercase();
    let mut rng = rng(hash(&encoding_rs::WINDOWS_1252.encode(&file).0));
    match &file[file.len() - 4..] {
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
    let mut random = rng(hash(&key));
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

fn compress(u: &[u8]) -> Vec<u8> {
    use LzssCode::*;
    let comparison = |lhs, rhs| match (lhs, rhs) {
        (Reference { len, pos: _ }, Reference { len: rlen, pos: _ }) => (rlen).cmp(&len),
        (Symbol(_), Symbol(_)) => std::cmp::Ordering::Equal,
        (_, Symbol(_)) => std::cmp::Ordering::Greater,
        (Symbol(_), _) => std::cmp::Ordering::Less,
    };
    let e = &mut LzssEncoder::with_dict(comparison, 0x400, 18, 3, 2, &[b' '; 0x400]);
    let iter = u.iter().cloned().encode(e, Action::Finish);
    let mut res = Vec::with_capacity(iter.size_hint().0 * 2);
    let mut op_idx = 0;
    let mut op_code = 1u8;
    let mut currpos = 0;
    iter.map(Result::unwrap).for_each(|code| {
        if op_code == 1 {
            op_idx = res.len();
            res.push(0);
        }
        currpos += match code {
            Symbol(b) => {
                res[op_idx] |= op_code;
                res.push(b);
                1
            }
            Reference { len, pos } => {
                let abspos = (currpos - pos - 16 - 1) & 0x3ff;
                res.push(abspos as u8);
                res.push((abspos >> 4) as u8 & 0x30 | (len as u8 - 3));
                len
            }
        };
        op_code = op_code.rotate_left(1);
    });
    res
}

pub fn decrypt(path: &std::path::Path) -> Result<Option<DecompressedFile>> {
    let mut reader = binrw::io::BufReader::new(std::fs::File::open(path)?);
    let os_str = path.file_name().ok_or(eyre!("Path {path:?} has no name"))?;
    let file_name = os_str
        .to_str()
        .ok_or(eyre!("{os_str:?} can't be converted to a String"))?;
    match DecompressedFile::read_args(&mut reader, (file_name,)) {
        Ok(res) => Ok(Some(res)),
        Err(e) if !matches!(e, binrw::Error::BadMagic { .. }) => Err(e.into()),
        _ => Ok(None),
    }
}

pub fn write_encrypted(path: &std::path::Path, game: Game, data: Vec<u8>) -> Result<()> {
    let os_str = path.file_name().ok_or(eyre!("Path {path:?} has no name"))?;
    let file_name = os_str
        .to_str()
        .ok_or(eyre!("{os_str:?} can't be converted to a String"))?;
    let mut cursor = std::io::Cursor::new(Vec::new());
    DecompressedFile { game, data }.write_args(&mut cursor, (file_name,))?;
    std::fs::write(path, cursor.into_inner())?;
    Ok(())
}
