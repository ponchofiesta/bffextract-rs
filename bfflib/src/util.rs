use std::{fs, mem};
use std::path::Path;
use std::slice::from_raw_parts_mut;
use std::io::{Read, Result};

/// Read binary data from a stream `reader` and map the bytes on the resulting
/// struct. Target struct needs to be packed.
pub(crate) fn read_struct<R: ?Sized + Read, T: Sized>(reader: &mut R) -> Result<T> {
    let mut obj: T = unsafe { mem::zeroed() };
    let size = mem::size_of::<T>();
    let buffer_slice = unsafe { from_raw_parts_mut(&mut obj as *mut _ as *mut u8, size) };
    reader.read_exact(buffer_slice)?;
    Ok(obj)
}

/// Create a directory and all of its parent directories if needed.
/// If some part of the path exists but is not a directory, it will be deleted and replaced by the directory.
pub(crate) fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    if path.as_ref().exists() {
        if path.as_ref().is_dir() {
            // Directory alread exists
            return Ok(());
        } else if path.as_ref().is_file() {
            fs::remove_file(&path)?;
        }
    }
    Ok(fs::create_dir_all(&path)?)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[derive(Debug, PartialEq)]
    #[repr(C, packed)]
    struct ReadStruct {
        pub a: u32,
        pub b: u16,
        pub c: u32,
    }

    #[test]
    fn read_struct_has_correct_fields() -> Result<()> {
        let mut stream = Cursor::new(b"\x01\x00\x00\x00\x02\x00\x03\x00\x00\x00\x10\x11");

        let result = read_struct::<Cursor<_>, ReadStruct>(&mut stream)?;

        let expected = ReadStruct { a: 1, b: 2, c: 3 };
        assert_eq!(result, expected);

        Ok(())
    }
}
