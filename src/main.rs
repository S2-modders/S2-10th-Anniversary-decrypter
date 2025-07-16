use simple_eyre::eyre::Result;

use decryptor_s2::*;

fn main() -> Result<()> {
    simple_eyre::install()?;
    std::env::args().collect::<Vec<String>>()[1..]
        .iter()
        .flat_map(walkdir::WalkDir::new)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .try_for_each(|entry: walkdir::DirEntry| -> Result<()> {
            let mut path = entry.path().to_owned();
            match decrypt(&path) {
                Ok(Some(decomp)) => {
                    let ext = match decomp.game {
                        Game::Adk => "adk.".to_owned(),
                        Game::Dng => "dng.".to_owned(),
                    };
                    path.set_extension(ext + path.extension().unwrap().to_str().unwrap());
                    std::fs::write(&path, decomp.data)?;
                    Ok(())
                }
                Ok(None) => {
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
                    write_encrypted(&path, game, std::fs::read(&path)?)
                }
                Err(e) => Err(e),
            }
        })
}

#[test]
fn is_valid() {
    use binrw::{BinRead, BinWrite};
    use simple_eyre::eyre::{Context, Result};
    let saved = std::env::args().collect::<Vec<String>>()[1..]
        .iter()
        .flat_map(walkdir::WalkDir::new)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| -> Result<isize> {
            let file_name = entry.path().file_name().unwrap().to_str().unwrap();
            match decrypt(entry.path()) {
                Ok(Some(decomp)) => {
                    let mut cursor = std::io::Cursor::new(Vec::new());
                    decomp.write_args(&mut cursor, (file_name,))?;
                    let mut cursor = std::io::Cursor::new(cursor.get_ref());
                    DecompressedFile::read_args(&mut cursor, (file_name,))
                        .wrap_err(format!("Error occurred in 2. decryption of {file_name}"))?;
                    Ok(entry.path().metadata().unwrap().len() as isize
                        - cursor.into_inner().len() as isize)
                }
                Ok(None) => Ok(0),
                Err(e) => Err(e.wrap_err("Error in 1. decryption of {}")),
            }
        })
        .map(Result::unwrap)
        .sum::<isize>();
    println!("saved {saved} bytes!");
}
