use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum BffError {
    BffReadError(BffReadError),
    BffExtractError(BffExtractError),
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

#[derive(Debug)]
pub enum BffReadError {
    IoError(std::io::Error),
    InvalidFileMagic(u32),
    InvalidRecordMagic(u16),
    EmptyFilename,
    BadSymbolTable,
    InvalidLevelIndex,
    InvalidTreelevel,
    FileToBig,
}

#[derive(Debug)]
pub enum BffExtractError {
    IoError(std::io::Error),
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
