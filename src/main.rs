use rayon::prelude::*;
use std::array::from_fn;
use std::env;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Game {
    DNG,
    ADK,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Header {
    game: Game,
    file_content_crc: u32,
    file_name_crc: u32,
    file_size: usize,
}

impl Header {
    fn from(vec: &[u8]) -> Result<Header, String> {
        if vec.len() < 20 {
            return Err(format!(
                "File too short to have a proper header: {} < 20",
                vec.len()
            ));
        }
        let header: Vec<u32> = vec
            .chunks(4)
            .take(5)
            .map(|chunk| chunk.try_into())
            .filter_map(Result::ok)
            .map(|chunk| u32::from_le_bytes(chunk))
            .collect();

        let magic = header[0];
        let fcc = header[1];
        let file_content_crc = header[2];
        let file_name_crc = header[3];
        let file_size = header[4] as usize;
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
        Ok(Header {
            game,
            file_content_crc,
            file_name_crc,
            file_size,
        })
    }

    fn add_to(&self, content: &mut Vec<u8>) {
        let fcc = match self.game {
            Game::ADK => 0x6b646173,
            Game::DNG => 0x30306372,
        };
        let size = self.file_size as u32;
        content.splice(
            0..0,
            [
                0x06091812,
                fcc,
                self.file_content_crc,
                self.file_name_crc,
                size,
            ]
            .iter()
            .flat_map(|num| num.to_le_bytes()),
        );
    }
}

pub struct Random {
    seed: u32,
}
impl Random {
    pub fn new(crc: u32) -> Self {
        let r_bit_positions: [u32; 8] = [0xC, 0x17, 0xA, 0x19, 0x8, 0x1B, 0x6, 0x1D];
        let mut seed = crc & 0x7fffffff;

        let population = seed.count_ones();

        // Set bits
        for i in 0..8 - population as i32 {
            seed |= 1 << r_bit_positions[i as usize];
        }

        // Remove bits
        if population > 24 {
            for i in 0..32 - population {
                seed &= !(1 << r_bit_positions[i as usize]);
            }
        }

        seed = if seed == 0 { 1 } else { seed & 0x7fffffff };

        Random { seed }
    }

    pub fn next_int(&mut self) -> u32 {
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
    let mut i = 0;
    let mut div = 0xffffffff;
    let int_data: Vec<u32> = data
        .chunks(4)
        .filter_map(|chunk| {
            if chunk.len() == 4 {
                Some(u32::from_le_bytes(chunk.try_into().unwrap()))
            } else {
                None
            }
        })
        .collect();

    // Process 32 bytes at a time
    while i + 32 <= data.len() {
        div ^= int_data[i / 4];
        for j in 1..8 {
            div = RNUM0[(div >> 24) as usize]
                ^ RNUM1[((div >> 16) & 0xff) as usize]
                ^ RNUM2[((div >> 8) & 0xff) as usize]
                ^ RNUM3[(div & 0xff) as usize]
                ^ int_data[j + i / 4];
        }
        div = RNUM0[(div >> 24) as usize]
            ^ RNUM1[((div >> 16) & 0xff) as usize]
            ^ RNUM2[((div >> 8) & 0xff) as usize]
            ^ RNUM3[(div & 0xff) as usize];
        i += 32;
    }

    // Process remaining 4 bytes at a time
    while i + 4 <= data.len() {
        div ^= int_data[i / 4];
        div = RNUM0[(div >> 24) as usize]
            ^ RNUM1[((div >> 16) & 0xff) as usize]
            ^ RNUM2[((div >> 8) & 0xff) as usize]
            ^ RNUM3[(div & 0xff) as usize];
        i += 4;
    }

    // Process remaining bytes one at a time
    while i < data.len() {
        div = (div >> 8) ^ RNUM0[(data[i] ^ (div as u8)) as usize];
        i += 1;
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
            let c = (16 - dc.len() as isize + curr as isize + (((next & 0xf0) as isize) << 4)
                & 0x3ff) as usize
                + dc.len();
            for i in 0..(next & 0xf) as usize + 3 {
                dc.push(if c + i < 1024 { b' ' } else { dc[c + i - 1024] });
            }
            mode >>= 1;
        }
    }
    dc
}

pub fn encrypt_decrypt(key: &[u8; 16], data: &mut [u8]) {
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
    let encoding = encoding_rs::WINDOWS_1252;
    let (encoded, _, _) = encoding.encode(&filename);

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
    if crc != header.file_name_crc {
        return Err(format!(
            "file name crc mismatch: {crc:#x} != {:#x} in {path}",
            header.file_name_crc
        ));
    }
    encrypt_decrypt(key, contents);
    let res = decompress(contents);
    let file_crc = gen_crc(&res);
    if res.len() != header.file_size {
        return Err(format!(
            "file size mismatch: {} != {} in {path}",
            res.len(),
            header.file_size,
        ));
    }
    if file_crc != header.file_content_crc {
        return Err(format!(
            "file data crc mismatch: {file_crc:#x} != {:#x} in {path}",
            header.file_content_crc,
        ));
    }
    Ok(res)
}

struct TreeNode {
    val: usize,
    parent: u32,
    larger: u32,
    smaller: u32,
}

impl TreeNode {
    fn new(val: usize) -> Self {
        TreeNode {
            val,
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
            tree[tree[old_idx].smaller as usize].parent = new_idx as u32;
        }
        tree[new_idx].larger = tree[old_idx].larger;
        tree[tree[old_idx].larger as usize].parent = new_idx as u32;
    }

    tree[new_idx].parent = tree[old_idx].parent;
    if tree[tree[old_idx].parent as usize].larger == old_idx as u32 {
        tree[tree[old_idx].parent as usize].larger = new_idx as u32;
    } else {
        tree[tree[old_idx].parent as usize].smaller = new_idx as u32;
    }

    tree[old_idx].parent = 0x400;
}

fn search(tree: &mut [TreeNode], copy_buffer: &[u8], new_idx: usize) -> (u32, u32) {
    let curr = copy_buffer[new_idx];
    let mut diff = 1;
    tree[new_idx] = TreeNode::new(new_idx);
    let mut curr_idx = (curr as usize) + 0x401;
    let mut copy_len = 0;
    let mut copy_offset = 0;

    if tree[curr_idx].larger == 0x400 {
        tree[curr_idx].larger = new_idx as u32;
        tree[new_idx].parent = curr_idx as u32;
        return (copy_len, copy_offset);
    }
    curr_idx = tree[curr_idx].larger as usize;

    loop {
        let mut curr_copy_len = 1;
        for _ in 1..18 {
            let idx_new = (new_idx + curr_copy_len) & 0x3FF;
            let idx_curr = (tree[curr_idx].val + curr_copy_len) & 0x3FF;
            diff = copy_buffer[idx_new] as i32 - copy_buffer[idx_curr] as i32;
            if diff != 0 {
                break;
            }
            curr_copy_len += 1;
        }

        if copy_len < curr_copy_len as u32 {
            copy_len = curr_copy_len as u32;
            copy_offset = curr_idx as u32;

            if curr_copy_len > 17 {
                copy_len = curr_copy_len as u32;
                copy_offset = curr_idx as u32;

                insert_node(tree, new_idx, curr_idx);
                return (copy_len, copy_offset);
            }
        }

        if diff < 0 {
            if tree[curr_idx].smaller == 0x400 {
                tree[curr_idx].smaller = new_idx as u32;
                tree[new_idx].parent = curr_idx as u32;
                return (copy_len, copy_offset);
            }
            curr_idx = tree[curr_idx].smaller as usize;
        } else {
            if tree[curr_idx].larger == 0x400 {
                tree[curr_idx].larger = new_idx as u32;
                tree[new_idx].parent = curr_idx as u32;
                return (copy_len, copy_offset);
            }
            curr_idx = tree[curr_idx].larger as usize;
        }
    }
}

fn insert_node(tree: &mut [TreeNode], new_idx: usize, curr_idx: usize) {
    tree[new_idx].parent = tree[curr_idx].parent;
    tree[new_idx].smaller = tree[curr_idx].smaller;
    tree[new_idx].larger = tree[curr_idx].larger;

    tree[tree[curr_idx].smaller as usize].parent = new_idx as u32;
    tree[tree[curr_idx].larger as usize].parent = new_idx as u32;

    let tmp = tree[curr_idx].parent;
    if tree[tmp as usize].larger == curr_idx as u32 {
        tree[tmp as usize].larger = new_idx as u32;
    } else {
        tree[tmp as usize].smaller = new_idx as u32;
    }
    tree[curr_idx].parent = 0x400;
}

fn compress_lzss(uncomp: &[u8]) -> Vec<u8> {
    let mut comp = vec![0u8; uncomp.len() * 9 / 8 + 1];
    let mut tree: [TreeNode; 1281] = from_fn(|i| TreeNode::new(i));
    let mut copy_buffer = [0x20u8; 1024];
    let mut comp_idx = 0;
    let mut uncomp_idx = 0;
    let mut op_idx = 0;
    let mut op_code = 0;
    let mut copy_buffer_idx = 0x3f0;
    let mut look_ahead_bytes = 0;
    let mut copy_len = 0;
    let mut copy_offset = 0;

    while look_ahead_bytes < 18 && uncomp.len() > uncomp_idx {
        copy_buffer[(look_ahead_bytes + 0x3f0) & 0x3ff] = uncomp[uncomp_idx];
        uncomp_idx += 1;
        look_ahead_bytes += 1;
    }

    for i in 0x3de..0x3f1 {
        (copy_len, copy_offset) = search(&mut tree, &copy_buffer, i);
    }

    while look_ahead_bytes > 0 {
        if look_ahead_bytes < copy_len as usize {
            copy_len = look_ahead_bytes as u32;
        }

        op_code <<= 1;
        if op_code == 0 {
            op_idx = comp_idx;
            comp_idx += 1;
            comp[op_idx] = 0;
            op_code = 1;
        }

        if copy_len < 3 {
            copy_len = 1;
            comp[op_idx] |= op_code;
            comp[comp_idx] = copy_buffer[copy_buffer_idx];
            comp_idx += 1;
        } else {
            comp[comp_idx] = copy_offset as u8;
            comp_idx += 1;
            comp[comp_idx] = (copy_offset >> 4) as u8 & 0xf0 | (copy_len - 3) as u8;
            comp_idx += 1;
        }

        for _ in 0..copy_len {
            copy_buffer_idx = (copy_buffer_idx + 1) & 0x3ff;
            delete_node(&mut tree, (copy_buffer_idx + 17) & 0x3ff);
            if uncomp_idx < uncomp.len() {
                copy_buffer[(copy_buffer_idx + 17) & 0x3ff] = uncomp[uncomp_idx];
                uncomp_idx += 1;
                (copy_len, copy_offset) = search(&mut tree, &copy_buffer, copy_buffer_idx);
            } else {
                look_ahead_bytes -= 1;
                if look_ahead_bytes > 0 {
                    (copy_len, copy_offset) = search(&mut tree, &copy_buffer, copy_buffer_idx);
                }
            }
        }
    }
    comp.truncate(comp_idx);
    comp
}

fn encrypt(key: &[u8; 16], contents: &[u8], game: Game) -> Vec<u8> {
    let mut comp = compress_lzss(contents);

    encrypt_decrypt(key, &mut comp);
    let file_content_crc = gen_crc(contents);
    let file_name_crc = gen_crc(key);
    let file_size = contents.len();
    let header = Header {
        game,
        file_content_crc,
        file_name_crc,
        file_size,
    };
    header.add_to(&mut comp);
    comp
}

fn main() {
    env::args()
        .collect::<Vec<String>>()
        .par_iter()
        .map(Path::new)
        .map(WalkDir::new)
        .map(WalkDir::into_iter)
        .flatten_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.path().to_path_buf())
        .map(|file| (file.clone(), std::fs::read(file).unwrap()))
        .map(|mut file| -> Result<_, String> {
            if let Ok(header) = Header::from(&file.1) {
                let key = make_key(&file.0, header.game);
                let res = decrypt(file.0.display(), &key, header, &mut file.1[20..])?;
                let ext = match header.game {
                    Game::ADK => "adk.",
                    Game::DNG => "dng.",
                };
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
            .flatten_iter()
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
                    let _ = decrypt(file.0.display(), &key, header, &mut contents[20..])?;
                    return Ok(file.1.len() as isize - 20 - contents.len() as isize);
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
