use std::fs;
use std::io::{Error, Result};
use std::path::Path;

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

/// Create the parent directory of the given path and all of its parent directories if needed.
/// If the parent directory already exists, it will not be modified.
pub(crate) fn create_parent_dir_all<D: AsRef<Path>>(destination: &D) -> Result<()> {
    let parent = destination.as_ref().parent().ok_or(Error::other(format!(
        "Missing parent directory for {}",
        destination.as_ref().display()
    )))?;
    create_dir_all(parent)
}

#[cfg(test)]
mod tests {
    use fs::File;
    use tempfile::tempdir;

    use super::*;

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
