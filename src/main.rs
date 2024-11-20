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
            let c = (num.wrapping_sub(dc.len()) + 0x400 - 0x3f0 & 0x3ff) + dc.len();
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
    match &file_name[file_name.len() - 4..] {
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
        if tree[tree[old_idx].smaller as usize].larger != 0x400 {
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
    if idx + 17 >= uncomp.len() {
        return (0, 0);
    }
    delete_node(tree, idx & 0x3ff);
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
    let currcomp = u128::from_be_bytes(uncomp[idx + 2..idx + 18].try_into().unwrap());

    loop {
        let c_idx = (curr.wrapping_sub(idx) & 0x3ff) + idx - 1024;
        let is_smaller = if uncomp[idx + 1] == uncomp[c_idx + 1] {
            let currcomp2 = u128::from_be_bytes(uncomp[c_idx + 2..c_idx + 18].try_into().unwrap());
            let curr_copy_len = (currcomp2 ^ currcomp).leading_zeros() as u8 / 8 + 2;
            if copy_len < curr_copy_len {
                copy_len = curr_copy_len;
                copy_offset = curr as u16;
                if curr_copy_len == 18 {
                    replace_node(tree, idx & 0x3ff, curr);
                    return (copy_len, copy_offset);
                }
            }
            currcomp < currcomp2
        } else {
            uncomp[idx + 1] < uncomp[c_idx + 1]
        };

        if is_smaller {
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

fn replace_node(tree: &mut [TreeNode], new_idx: usize, curr_idx: usize) {
    tree[new_idx] = tree[curr_idx].clone();
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
        .for_each(|mut file| {
            if let Ok(header) = Header::try_from(file.1.as_slice()) {
                let key = make_key(&file.0, header.game);
                let res = decrypt(key, header, &mut file.1[20..])
                    .map_err(|e| {
                        format!("Error occurred while decrypting {}:\n{e}", file.0.display())
                    })
                    .unwrap();

                let ext = match header.game {
                    Game::ADK => "adk.",
                    Game::DNG => "dng.",
                };
                file.0
                    .set_extension(ext.to_owned() + file.0.extension().unwrap().to_str().unwrap());
                std::fs::write(&file.0, &res)
                    .unwrap_or_else(|_| panic!("could not write to {}", file.0.display()));
            } else {
                let file_stem = file.0.file_stem().unwrap().to_str().unwrap();
                let game = match &file_stem[file_stem.len() - 4..] {
                    ".adk" => Game::ADK,
                    ".dng" => Game::DNG,
                    _ => return,
                };
                file.0.set_file_name(
                    file_stem[..file_stem.len() - 3].to_owned()
                        + file.0.extension().unwrap().to_str().unwrap(),
                );
                let content = encrypt(make_key(&file.0, game), &file.1, game);
                std::fs::write(&file.0, &content)
                    .unwrap_or_else(|_| panic!("could not write to {}", file.0.display()));
            }
        })
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
            .map(|mut file| -> isize {
                if let Ok(header) = Header::try_from(file.1.as_slice()) {
                    let path = file.0.display();
                    let key = make_key(&file.0, header.game);
                    let res = decrypt(key, header, &mut file.1[20..])
                        .map_err(|e| format!("Error occurred in 1. decryption {path}:\n{e}"))
                        .unwrap();
                    let mut contents = encrypt(key, &res, header.game);
                    assert_eq!(
                        header,
                        Header::try_from(contents.as_slice())
                            .map_err(|e| format!("Error occurred while in 2. header {path}:\n{e}"))
                            .unwrap()
                    );
                    decrypt(key, header, &mut contents[20..])
                        .map_err(|e| format!("Error occurred in 2. decryption {path}:\n{e}"))
                        .unwrap();
                    return file.1.len() as isize - contents.len() as isize;
                }
                0
            })
            .sum::<isize>();
        println!("saved {saved} bytes!");
    }
}
