use rayon::prelude::*;
use std::env;
use std::path::Path;
use std::slice::from_raw_parts;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
enum FormatError {
    #[error("File too short to have a proper header: {0} < 20")]
    FileTooShort(usize),
    #[error("Not an encrypted file: magic does not match: {0:#x} != 0x6091812")]
    NotEncryptedFile(u32),
    #[error("No matching game header found for fcc {0:#x}")]
    NoGameFccFound(u32),
}
#[derive(Error, Debug)]
enum DecryptError {
    #[error("file name crc mismatch: {0:#x} != {1:#x}")]
    NameCrcMismatch(u32, u32),
    #[error("file crc mismatch: {0:#x} != {1:#x}")]
    FileCrcMismatch(u32, u32),
    #[error("file size mismatch: {0} != {1}")]
    SizeMismatch(u32, u32),
}
#[derive(Error, Debug)]
enum CryptError {
    #[error("Error occurred while decryping:\n{0}")]
    DecryptError(#[from] DecryptError),
    #[error("Error occurred while parsing header:\n{0}")]
    FormatError(#[from] FormatError),
    #[error("Error occurred while writing:\n{0}")]
    IOError(#[from] std::io::Error),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Game {
    DNG = 0x30306372,
    ADK = 0x6b646173,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header {
    game: Game,
    file_crc: u32,
    name_crc: u32,
    size: u32,
}
impl TryFrom<&[u8]> for Header {
    type Error = FormatError;
    fn try_from(vec: &[u8]) -> Result<Self, Self::Error> {
        if vec.len() < 20 {
            return Err(FormatError::FileTooShort(vec.len()));
        }
        let header = unsafe { from_raw_parts(vec.as_ptr() as *const u32, 5) };
        if header[0] != 0x06091812 {
            return Err(FormatError::NotEncryptedFile(header[0]));
        }
        Ok(Header {
            game: match header[1] {
                0x6b646173 => Game::ADK,
                0x30306372 => Game::DNG,
                fcc => return Err(FormatError::NoGameFccFound(fcc)),
            },
            file_crc: header[2],
            name_crc: header[3],
            size: header[4],
        })
    }
}

struct Random {
    seed: u32,
}
impl Random {
    fn new(crc: u32) -> Self {
        const RANDOM_INT_POS: [u32; 8] = [0xC, 0x17, 0xA, 0x19, 0x8, 0x1B, 0x6, 0x1D];
        let mut seed = crc & 0x7fffffff;

        let population = seed.count_ones() as usize;
        // Set bits
        for i in population..8 {
            seed |= 1 << RANDOM_INT_POS[i - population];
        }
        // Remove bits
        for i in 24..population {
            seed &= !(1 << RANDOM_INT_POS[i - 24]);
        }
        Random { seed }
    }

    fn next_int(&mut self) -> u32 {
        let mul = (self.seed as u64) * 0x41a7;
        self.seed = (mul as u32 & 0x7fffffff) + (mul >> 31) as u32;
        self.seed
    }
}

const RNUM0: [u32; 256] = include_bytes_plus::include_bytes!("rnum0.bin" as u32);
const RNUM1: [u32; 256] = include_bytes_plus::include_bytes!("rnum1.bin" as u32);
const RNUM2: [u32; 256] = include_bytes_plus::include_bytes!("rnum2.bin" as u32);
const RNUM3: [u32; 256] = include_bytes_plus::include_bytes!("rnum3.bin" as u32);
fn gen_crc(data: &[u8]) -> u32 {
    let mut div = 0xffffffff;
    let int_data = unsafe { from_raw_parts(data.as_ptr() as *const u32, data.len() / 4) };
    for i in 0..int_data.len() {
        div ^= int_data[i];
        div = RNUM0[(div >> 24) as usize]
            ^ RNUM1[((div >> 16) & 0xff) as usize]
            ^ RNUM2[((div >> 8) & 0xff) as usize]
            ^ RNUM3[(div & 0xff) as usize];
    }
    for i in data.len() & !3..data.len() {
        div = (div >> 8) ^ RNUM0[(data[i] ^ div as u8) as usize];
    }
    !div
}

fn decompress(cmp: &[u8]) -> Vec<u8> {
    let mut dc = Vec::with_capacity(cmp.len() * 9 / 8);
    let mut mode = 0;
    let mut iter = cmp.iter();
    while let Some(&curr) = iter.next() {
        if mode & 0x100 == 0 {
            mode = curr as u32 | 0xff00;
        } else if mode & 1 != 0 {
            dc.push(curr);
            mode >>= 1;
        } else if let Some(&next) = iter.next() {
            let num = curr as isize + ((next as isize & 0x30) << 4);
            let c = (num - dc.len() as isize - 0x3f0 & 0x3ff) as usize + dc.len();
            for i in 0..3 + (next as usize & 0xf) {
                dc.push(if c + i < 1024 { b' ' } else { dc[c + i - 1024] });
            }
            mode >>= 1;
        }
    }
    dc
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

fn make_key(file_path: &Path, game: Game) -> [u8; 16] {
    let key = match game {
        Game::ADK => 0xbd8cc2bd30674bf8b49b1bf9f6822ef4u128.to_be_bytes(),
        Game::DNG => 0xc95946cad9f04f0aa100aab8cbe8db6bu128.to_be_bytes(),
    };
    let file_name = file_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap()
        .to_ascii_lowercase();
    let mut rng = Random::new(gen_crc(&encoding_rs::WINDOWS_1252.encode(&file_name).0));
    match &file_name[file_name.len() - 4..file_name.len()] {
        ".s2m" | ".sav" => return key,
        _ => key.map(|byte| byte ^ rng.next_int() as u8),
    }
}

fn decrypt(key: [u8; 16], header: Header, contents: &mut [u8]) -> Result<Vec<u8>, DecryptError> {
    let crc = gen_crc(&key);
    if crc != header.name_crc {
        return Err(DecryptError::NameCrcMismatch(crc, header.name_crc));
    }
    encrypt_decrypt(key, contents);
    let res = decompress(contents);
    if res.len() != header.size.try_into().unwrap() {
        return Err(DecryptError::SizeMismatch(res.len() as u32, header.size));
    }
    let file_crc = gen_crc(&res);
    if file_crc != header.file_crc {
        return Err(DecryptError::FileCrcMismatch(file_crc, header.file_crc));
    }
    Ok(res)
}

#[derive(Copy, Clone)]
struct TreeNode {
    parent: u16,
    larger: u16,
    smaller: u16,
}

impl TreeNode {
    fn new() -> Self {
        TreeNode {
            parent: 0x400,
            larger: 0x400,
            smaller: 0x400,
        }
    }
}

fn delete_node(tree: &mut [TreeNode], old_idx: usize) {
    if tree[old_idx].parent == 0x400 {
        return;
    }

    let mut new_idx = if tree[old_idx].smaller != 0x400 {
        tree[old_idx].smaller
    } else {
        tree[old_idx].larger
    } as usize;

    if tree[old_idx].larger != 0x400 && tree[old_idx].smaller != 0x400 {
        if tree[new_idx].larger != 0x400 {
            while tree[new_idx].larger != 0x400 {
                new_idx = tree[new_idx].larger as usize;
            }
            tree[tree[new_idx].smaller as usize].parent = tree[new_idx].parent;

            tree[tree[new_idx].parent as usize].larger = tree[new_idx].smaller;
            tree[new_idx].smaller = tree[old_idx].smaller;
            tree[tree[old_idx].smaller as usize].parent = new_idx as u16;
        }
        tree[new_idx].larger = tree[old_idx].larger;
        tree[tree[old_idx].larger as usize].parent = new_idx as u16;
    }

    tree[new_idx].parent = tree[old_idx].parent;
    change_parent(tree, old_idx, new_idx);
}

fn change_parent(tree: &mut [TreeNode], old_idx: usize, new_idx: usize) {
    if tree[tree[old_idx].parent as usize].larger == old_idx as u16 {
        tree[tree[old_idx].parent as usize].larger = new_idx as u16;
    } else {
        tree[tree[old_idx].parent as usize].smaller = new_idx as u16;
    }

    tree[old_idx].parent = 0x400;
}

fn search(tree: &mut [TreeNode], idx: usize, uncomp: &[u8]) -> (u8, u16) {
    if idx + 18 > uncomp.len() {
        return (0, 0);
    }
    delete_node(tree, (idx + 17) & 0x3ff);
    let mut diff = 1;
    tree[idx & 0x3ff] = TreeNode::new();
    let mut curr = uncomp[idx] as usize + 0x400 + 1;
    let mut copy_len = 0;
    let mut copy_offset = 0;

    if tree[curr].larger == 0x400 {
        tree[curr].larger = (idx & 0x3ff) as u16;
        tree[idx & 0x3ff].parent = curr as u16;
        return (copy_len, copy_offset);
    }
    curr = tree[curr].larger as usize;

    loop {
        let mut curr_copy_len = 18;
        let idx_curr = (curr as isize - idx as isize & 0x3ff) as usize + idx - 1024;
        for i in 1..18 {
            diff = uncomp[idx + i] as i32 - uncomp[idx_curr + i] as i32;
            if diff != 0 {
                curr_copy_len = i as u8;
                break;
            }
        }

        if copy_len < curr_copy_len {
            copy_len = curr_copy_len;
            copy_offset = curr as u16;
            if curr_copy_len == 18 {
                insert_node(tree, idx & 0x3ff, curr);
                return (copy_len, copy_offset);
            }
        }

        if diff > 0 {
            if tree[curr].larger == 0x400 {
                tree[curr].larger = (idx & 0x3ff) as u16;
                tree[idx & 0x3ff].parent = curr as u16;
                return (copy_len, copy_offset);
            }
            curr = tree[curr].larger as usize;
        } else {
            if tree[curr].smaller == 0x400 {
                tree[curr].smaller = (idx & 0x3ff) as u16;
                tree[idx & 0x3ff].parent = curr as u16;
                return (copy_len, copy_offset);
            }
            curr = tree[curr].smaller as usize;
        }
    }
}

fn insert_node(tree: &mut [TreeNode], new_idx: usize, curr_idx: usize) {
    tree[new_idx].parent = tree[curr_idx].parent;
    tree[new_idx].smaller = tree[curr_idx].smaller;
    tree[new_idx].larger = tree[curr_idx].larger;

    tree[tree[curr_idx].smaller as usize].parent = new_idx as u16;
    tree[tree[curr_idx].larger as usize].parent = new_idx as u16;
    change_parent(tree, curr_idx, new_idx);
}

fn compress_lzss(uncomp: &[u8]) -> Vec<u8> {
    let mut comp = Vec::with_capacity(uncomp.len());
    let mut tree = [TreeNode::new(); 1024 + 1 + 256];
    let mut op_idx = 0;
    let mut op_code = 0;
    let mut consume = 0;

    for i in 0..uncomp.len() {
        let (copy_len, copy_offset) = search(&mut tree, i, uncomp);
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

fn main() {
    env::args()
        .collect::<Vec<String>>()
        .into_iter()
        .skip(1)
        .flat_map(WalkDir::new)
        .par_bridge()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .map(|file| (file.clone(), std::fs::read(file).unwrap()))
        .map(|mut file| -> Result<(), CryptError> {
            if let Ok(header) = Header::try_from(file.1.as_slice()) {
                let ext = match header.game {
                    Game::ADK => "adk.",
                    Game::DNG => "dng.",
                };
                let key = make_key(&file.0, header.game);
                let res = decrypt(key, header, &mut file.1[20..])?;
                file.0
                    .set_extension(ext.to_owned() + file.0.extension().unwrap().to_str().unwrap());
                std::fs::write(&file.0, &res)?;
            } else {
                let file_stem = file.0.file_stem().unwrap().to_str().unwrap();
                let game = if file_stem.ends_with(".adk") {
                    Game::ADK
                } else if file_stem.ends_with(".dng") {
                    Game::DNG
                } else {
                    return Ok(());
                };
                file.0.set_file_name(
                    file_stem[..file_stem.len() - 4].to_owned()
                        + "."
                        + file.0.extension().unwrap().to_str().unwrap(),
                );
                let content = encrypt(make_key(&file.0, game), &file.1, game);
                std::fs::write(&file.0, content)?;
            }
            Ok(())
        })
        .filter_map(Result::err)
        .for_each(|e| panic!("{e}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn is_valid() {
        let saved = env::args()
            .collect::<Vec<String>>()
            .into_iter()
            .skip(1)
            .flat_map(WalkDir::new)
            .par_bridge()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.path().to_path_buf())
            .map(|file| (file.clone(), std::fs::read(file).unwrap()))
            .map(|mut file| -> Result<isize, CryptError> {
                if let Ok(header) = Header::try_from(file.1.as_slice()) {
                    let key = make_key(&file.0, header.game);
                    let res = decrypt(key, header, &mut file.1[20..])?;
                    let mut contents = encrypt(key, &res, header.game);
                    assert_eq!(header, Header::try_from(contents.as_slice())?);
                    decrypt(key, header, &mut contents[20..])?;
                    return Ok(file.1.len() as isize - contents.len() as isize);
                }
                Ok(0)
            })
            .map(|res| {
                return match res {
                    Ok(val) => val,
                    Err(e) => panic!("{e}"),
                };
            })
            .sum::<isize>();
        println!("saved {saved} bytes!");
    }
}
