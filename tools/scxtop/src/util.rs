use anyhow::Result;
use std::fs;
use std::io::Read;

/// Returns the file content as a String.
pub fn read_file_string(path: &str) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}
