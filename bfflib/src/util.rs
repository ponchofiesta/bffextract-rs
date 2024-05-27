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
    use fs::File;
    use tempfile::tempdir;

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

    #[test]
    fn test_create_dir_all_new() {
        // Create a temporary directory path
        let temp_dir = tempdir().unwrap();
        let new_dir_path = temp_dir.path().join("test_create_dir_all_new");

        // Ensure the directory does not exist
        assert!(!new_dir_path.exists());

        // Create the directory
        create_dir_all(&new_dir_path).unwrap();

        // Check if the directory exists
        assert!(new_dir_path.exists());
        assert!(new_dir_path.is_dir());
    }

    #[test]
    fn test_create_dir_all_existing_dir() {
        // Create a temporary directory path
        let temp_dir = tempdir().unwrap();
        let existing_dir_path = temp_dir.path().join("existing_dir");

        // Create the directory initially
        fs::create_dir(&existing_dir_path).unwrap();

        // Ensure the directory exists
        assert!(existing_dir_path.exists());
        assert!(existing_dir_path.is_dir());

        // Call create_dir_all on the existing directory
        create_dir_all(&existing_dir_path).unwrap();

        // Check if the directory still exists
        assert!(existing_dir_path.exists());
        assert!(existing_dir_path.is_dir());
    }

    #[test]
    fn test_create_dir_all_replace_file() {
        // Create a temporary directory path
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file");

        // Create a file at the path
        File::create(&file_path).unwrap();

        // Ensure the file exists
        assert!(file_path.exists());
        assert!(file_path.is_file());

        // Call create_dir_all on the path with the existing file
        create_dir_all(&file_path).unwrap();

        // Check if the file was replaced by a directory
        assert!(file_path.exists());
        assert!(file_path.is_dir());
    }
}
