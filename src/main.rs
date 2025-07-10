use binrw::{error::ContextExt, io::BufReader, BinRead, BinWrite};
use simple_eyre::eyre::{Context, Result};
use std::{fs::File, io::Read};

use decryptor_s2::*;

fn main() -> Result<()> {
    simple_eyre::install()?;
    std::env::args().collect::<Vec<String>>()[1..]
        .iter()
        .flat_map(walkdir::WalkDir::new)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .try_for_each(handle_file)
}

fn handle_file(entry: walkdir::DirEntry) -> Result<()> {
    let mut path = entry.path().to_owned();
    let mut reader = BufReader::new(File::open(entry.path())?);
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
                .with_context(format!("Error decrypting {file_name}:"))
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
}

#[test]
fn is_valid() {
    use rayon::prelude::*;
    let saved = std::env::args().collect::<Vec<String>>()[1..]
        .iter()
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
                    let mut cursor = std::io::Cursor::new(cursor.get_ref());
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
