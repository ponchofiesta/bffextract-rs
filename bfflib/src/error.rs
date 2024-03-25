use std::fmt::Display;

pub type Result<T> = core::result::Result<T, Error>;

/// General error wrapping more specific errors.
#[derive(Debug)]
pub enum Error {
    // Read errors
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
    /// A filename was not found in archive
    FileNotFound,
    /// A record contains unsupported file type
    UnsupportedFileType,

    // Extraction errors
    /// File system entry mode could not be set. Typically should contain a `std::io::error`.
    #[allow(dead_code)]
    ModeError(Box<dyn std::error::Error>),
    /// The record has no parent directory. This should never occur.
    MissingParentDir(String),

    // Other errors
    /// `std::io:error` occured.
    IoError(std::io::Error),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;

        match self {
            // Read errors
            BadSymbolTable => write!(f, "Invalid file format: Bad symbol table."),
            EmptyFilename => {
                write!(f, "Record having an empty filename will be skipped.")
            }
            FileToBig => write!(f, "The file size is to big. Has to be max 4 GiB."),
            InvalidFileMagic(magic) => write!(
                f,
                "Invalid file format: File has an invalid magic number '{magic}'."
            ),
            InvalidLevelIndex => {
                write!(f, "Invalid file format: Invalid level index found.")
            }
            InvalidRecordMagic(magic) => write!(
                f,
                "Invalid file format: Record has an invalid magic number '{magic}'."
            ),
            InvalidRecord => write!(f, "Invalid or unsupported record found."),
            InvalidTreelevel => {
                write!(f, "Invalid file format: Invalid tree levels.")
            }
            FileNotFound => write!(f, "Filename wasn't found in archive."),
            UnsupportedFileType => write!(f, "The file type of the record is unsupported."),

            // Extraction errors
            ModeError(mode_error) => {
                write!(f, "Failed to set file modes: {mode_error}")
            }
            MissingParentDir(path) => write!(f, "Directory is impossible: {path}"),

            // Other errors
            IoError(io_error) => write!(f, "{io_error}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IoError(value)
    }
}
