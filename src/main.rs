use rayon::prelude::*;
use std::env;
use std::path::Path;
use std::slice::from_raw_parts;
use walkdir::WalkDir;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Game {
    DNG,
    ADK,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header {
    game: Game,
    file_crc: u32,
    name_crc: u32,
    size: usize,
}

impl Header {
    fn new(game: Game, file_crc: u32, name_crc: u32, size: usize) -> Self {
        Self {
            game,
            file_crc,
            name_crc,
            size,
        }
    }

    fn from(vec: &[u8]) -> Result<Header, String> {
        if vec.len() < 20 {
            return Err(format!(
                "File too short to have a proper header: {} < 20",
                vec.len()
            ));
        }
        let header = unsafe { from_raw_parts(vec.as_ptr() as *const u32, 5) };
        let magic = header[0];
        let fcc = header[1];
        if magic != 0x06091812 {
            return Err(format!(
                "Not an encrypted file: magic does not match: {magic:#x} != 0x6091812"
            ));
        };
        let game = match fcc {
            0x6b646173 => Game::ADK,
            0x30306372 => Game::DNG,
            _ => return Err(format!("No matching game header found for fcc {fcc:#x}")),
        };
        Ok(Header::new(game, header[2], header[3], header[4] as usize))
    }

    fn add_to(&self, content: &mut Vec<u8>) {
        let fcc = match self.game {
            Game::ADK => 0x6b646173,
            Game::DNG => 0x30306372,
        };
        content.splice(
            0..0,
            [
                0x06091812,
                fcc,
                self.file_crc,
                self.name_crc,
                self.size as u32,
            ]
            .iter()
            .flat_map(|num| num.to_le_bytes()),
        );
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

        if seed == 0 {
            seed = 1;
        }
        Random { seed }
    }

    fn next_int(&mut self) -> u32 {
        let upper = (self.seed >> 0x10) * 0x41A7;
        let lower = (self.seed & 0xFFFF) * 0x41A7;
        self.seed = lower + (upper & 0x7FFF) * 0x10000;

        if self.seed > 0x7FFFFFFF {
            self.seed = (self.seed & 0x7FFFFFFF) + 1;
        }
        self.seed += upper >> 15;
        if self.seed > 0x7FFFFFFF {
            self.seed = (self.seed & 0x7FFFFFFF) + 1;
        }
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
            let num = curr as usize + ((next as usize & 0x30) << 4);
            let c = (num - dc.len() - 0x3f0 & 0x3ff) + dc.len();
            for i in 0..3 + (next as usize & 0xf) {
                dc.push(if c + i < 1024 { b' ' } else { dc[c + i - 1024] });
            }
            mode >>= 1;
        }
    }
    dc
}

fn encrypt_decrypt(key: &[u8; 16], data: &mut [u8]) {
    let mut random = Random::new(gen_crc(key));

    let flavor1: Vec<u8> = (0..(random.next_int() & 0x7F) + 0x80)
        .map(|_| random.next_int() as u8)
        .collect();

    for i in 0..data.len() {
        data[i] ^= flavor1[i % flavor1.len()];
    }

    let flavor2: Vec<u8> = (0..(random.next_int() & 0xF) + 0x11)
        .map(|_| random.next_int() as u8)
        .collect();
    let mut i = random.next_int() as usize % data.len();
    let offset = (random.next_int() & 0x1FFF) as usize + 0x2000;

    while i < data.len() {
        data[i] ^= flavor2[(key[i % key.len()] as usize ^ i) % flavor2.len()];
        i += offset as usize;
    }
}

fn make_key(filepath: &Path, game: Game) -> [u8; 16] {
    let mut key = match game {
        Game::ADK => 0xbd8cc2bd30674bf8b49b1bf9f6822ef4u128.to_be_bytes(),
        Game::DNG => 0xc95946cad9f04f0aa100aab8cbe8db6bu128.to_be_bytes(),
    };
    let filename = filepath
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    let (encoded, _, _) = encoding_rs::WINDOWS_1252.encode(&filename);

    if filepath.extension().unwrap() == "s2m" || filepath.extension().unwrap() == "sav" {
        return key;
    }
    let mut rng = Random::new(gen_crc(&encoded));
    for byte in key.iter_mut() {
        *byte ^= rng.next_int() as u8;
    }
    key
}

fn decrypt(
    path: std::path::Display,
    key: &[u8; 16],
    header: Header,
    contents: &mut [u8],
) -> Result<Vec<u8>, String> {
    let crc = gen_crc(key);
    if crc != header.name_crc {
        return Err(format!(
            "file name crc mismatch: {crc:#x} != {:#x} in {path}",
            header.name_crc
        ));
    }
    encrypt_decrypt(key, contents);
    let res = decompress(contents);
    let file_crc = gen_crc(&res);
    if res.len() != header.size {
        return Err(format!(
            "file size mismatch: {} != {} in {path}",
            res.len(),
            header.size,
        ));
    }
    if file_crc != header.file_crc {
        return Err(format!(
            "file data crc mismatch: {file_crc:#x} != {:#x} in {path}",
            header.file_crc,
        ));
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
        let idx_curr = ((curr - idx) & 0x3ff) + idx - 1024;
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
        delete_node(&mut tree, (i + 17) & 0x3ff);
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
                comp.push(copy_offset as u8 + 0xf0);
                comp.push(((copy_offset + 0x3f0) >> 4) as u8 & 0xf0 | copy_len - 3);
                consume = copy_len;
            }
        }
        consume -= 1;
    }
    comp
}

fn encrypt(key: &[u8; 16], contents: &[u8], game: Game) -> Vec<u8> {
    let mut comp = compress_lzss(contents);
    encrypt_decrypt(key, &mut comp);
    Header::new(game, gen_crc(contents), gen_crc(key), contents.len()).add_to(&mut comp);
    comp
}

fn main() {
    env::args()
        .collect::<Vec<String>>()
        .par_iter()
        .map(Path::new)
        .map(WalkDir::new)
        .map(WalkDir::into_iter)
        .map(|iter| iter.par_bridge())
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .map(|file| (file.clone(), std::fs::read(file).unwrap()))
        .map(|mut file| -> Result<_, String> {
            if let Ok(header) = Header::from(&file.1) {
                let ext = match header.game {
                    Game::ADK => "adk.",
                    Game::DNG => "dng.",
                };
                let key = make_key(&file.0, header.game);
                let res = decrypt(file.0.display(), &key, header, &mut file.1[20..])?;
                file.0
                    .set_extension(ext.to_owned() + file.0.extension().unwrap().to_str().unwrap());
                std::fs::write(&file.0, &res)
                    .expect(format!("Failed to write to {}", file.0.display()).as_str());
            } else {
                let file_stem = file.0.file_stem().unwrap().to_str().unwrap();
                let game = if file_stem.ends_with(".adk") {
                    Game::ADK
                } else if file_stem.ends_with(".dng") {
                    Game::DNG
                } else {
                    return Ok(());
                };
                let content = encrypt(&make_key(&file.0, game), &file.1, game);
                file.0.set_file_name(
                    file_stem[..file_stem.len() - 4].to_owned()
                        + "."
                        + file.0.extension().unwrap().to_str().unwrap(),
                );
                std::fs::write(&file.0, content)
                    .expect(format!("Failed to write to {}", file.0.display()).as_str());
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
            .par_iter()
            .map(Path::new)
            .map(WalkDir::new)
            .map(WalkDir::into_iter)
            .map(|iter| iter.par_bridge())
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.path().to_path_buf())
            .map(|file| (file.clone(), std::fs::read(file).unwrap()))
            .map(|mut file| -> Result<isize, String> {
                if let Ok(header) = Header::from(&file.1) {
                    let key = make_key(&file.0, header.game);
                    let res = decrypt(file.0.display(), &key, header, &mut file.1[20..])?;
                    let mut contents = encrypt(&key, &res, header.game);
                    assert_eq!(header, Header::from(&contents)?);
                    decrypt(file.0.display(), &key, header, &mut contents[20..])?;
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
