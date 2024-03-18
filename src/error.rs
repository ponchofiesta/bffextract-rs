use std::error::Error;
use std::fmt::Display;

/// General error wrapping more specific errors.
#[derive(Debug)]
pub enum BffError {
    /// A read error occured.
    BffReadError(BffReadError),
    /// Typically a write error occured while extracting files. But may also contain a read error.
    BffExtractError(BffExtractError),
    /// The record has no parent directory. This should never occur.
    MissingParentDir(String),
}

impl Error for BffError {}

impl From<BffReadError> for BffError {
    fn from(value: BffReadError) -> Self {
        BffError::BffReadError(value)
    }
}

impl From<BffExtractError> for BffError {
    fn from(value: BffExtractError) -> Self {
        BffError::BffExtractError(value)
    }
}

impl Display for BffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BffError::BffExtractError(e) => write!(f, "Failed to extract BFF file: {e}"),
            BffError::BffReadError(e) => write!(f, "Failed to read BFF file: {e}"),
            BffError::MissingParentDir(path) => write!(f, "Directory is impossible: {path}"),
        }
    }
}

/// Errors when reading BFF file.
#[derive(Debug)]
pub enum BffReadError {
    /// `std::io:error` occured.
    IoError(std::io::Error),
    /// The file had an invalid magic number. Provides the magic number read.
    InvalidFileMagic(u32),
    /// An record had an invalid magic number. Provides the magic number read.
    InvalidRecordMagic(u16),
    /// The record was invalid. This also may indicate some unsupported features.
    InvalidRecord,
    /// The record had an empty file name.
    EmptyFilename,
    /// The decoding table of the record is invalid.
    BadSymbolTable,
    /// The decoding table of the record is invalid.
    InvalidLevelIndex,
    /// The decoding table of the record is invalid.
    InvalidTreelevel,
    /// File size is bigger than 4 GiB. Actually the lib doesn't support larger files.
    FileToBig,
}

/// Errors when extracting BFF file, especially when writing its content.
#[derive(Debug)]
pub enum BffExtractError {
    /// Some generic IO error occured. Mosly a write error but may also be a read error.
    IoError(std::io::Error),
    /// File system entry mode could not be set. Typically should contain a `std::io::error`.
    #[allow(dead_code)]
    ModeError(Box<dyn Error>),
}

impl Error for BffReadError {}

impl Error for BffExtractError {}

impl Display for BffReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BffReadError::BadSymbolTable => write!(f, "Invalid file format: Bad symbol table."),
            BffReadError::EmptyFilename => {
                write!(f, "Record having an empty filename will be skipped.")
            }
            BffReadError::FileToBig => write!(f, "The file size is to big. Has to be max 4 GiB."),
            BffReadError::InvalidFileMagic(magic) => write!(
                f,
                "Invalid file format: File has an invalid magic number '{magic}'."
            ),
            BffReadError::InvalidLevelIndex => {
                write!(f, "Invalid file format: Invalid level index found.")
            }
            BffReadError::InvalidRecordMagic(magic) => write!(
                f,
                "Invalid file format: Record has an invalid magic number '{magic}'."
            ),
            BffReadError::InvalidRecord => write!(f, "Invalid or unsupported record found."),
            BffReadError::InvalidTreelevel => {
                write!(f, "Invalid file format: Invalid tree levels.")
            }
            BffReadError::IoError(io_error) => write!(f, "{io_error}"),
        }
    }
}

impl Display for BffExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BffExtractError::IoError(io_error) => {
                write!(f, "Failed to extract BFF file: {io_error}")
            }
            BffExtractError::ModeError(mode_error) => {
                write!(f, "Failed to set file modes: {mode_error}")
            }
        }
    }
}

impl From<std::io::Error> for BffReadError {
    fn from(value: std::io::Error) -> Self {
        BffReadError::IoError(value)
    }
}

impl From<std::io::Error> for BffExtractError {
    fn from(value: std::io::Error) -> Self {
        BffExtractError::IoError(value)
    }
}
