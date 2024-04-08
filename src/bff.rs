use crate::error::{BffError, BffReadError};
use crate::huffman::HuffmanReader;
use crate::{error, huffman, util};
use chrono::prelude::*;
#[cfg(unix)]
use file_mode::ModePath;
use file_mode::{FileType, Mode};
use filetime::{set_file_times, FileTime};
use normalize_path::NormalizePath;
use std::fmt::Display;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// All BFF files should contain this magic number.
pub const FILE_MAGIC: u32 = 0xea6b0009; //0x09006BEA;
/// A compressed record should contain this magic number.
pub const HUFFMAN_MAGIC: u16 = 0xEA6C;
/// All records should contain one of these magic numbers.
pub const HEADER_MAGICS: [u16; 3] = [0xEA6B, HUFFMAN_MAGIC, 0xEA6D];

/// Representation of the file header.
///
/// Some data is not identified at the moment and named "unk*"
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FileHeader {
    /// Magic number
    pub magic: u32,
    pub checksum: u32,
    pub current_date: u32,
    pub starting_date: u32,
    pub unk10: u32,
    pub disk_name: [u8; 8],
    pub unk1_c: u32,
    pub unk20: u32,
    pub filesystem_name: [u8; 8],
    pub unk2_c: u32,
    pub unk30: u32,
    /// Typically contains the username of the build user.
    pub username: [u8; 8],
    pub unk3_c: u32,
    pub unk40: u32,
    pub unk44: u32,
}

/// Represntation of a record header.
///
/// Some data is not identified at the moment and named "unk*"
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordHeader {
    /// Directories seems to have 0x0D, files found having 0x0F, 0x10, 0x11, 0x12; lpp_name has 0x0A
    pub unk00: u8,
    /// typical record has 0x0B, some offset data found having 0x07
    pub unk01: u8,
    /// Magic number
    pub magic: u16,
    pub unk04: u32,
    /// Maybe directory ID or counter, always 0 for files
    pub unk08: u32,
    /// File mode (rwx...) as bit represntation
    pub mode: u32,
    /// User ID number of the file
    pub uid: u32,
    /// Group ID number of the file
    pub gid: u32,
    /// File size
    pub size: u32,
    pub atime: u32,
    /// Last modified timestamp of the file
    pub mtime: u32,
    pub time24: u32,
    /// Always last bits: 1010 (10)
    pub unk28: u32,
    /// Always last bits: 111 (7)
    pub unk2_c: u32,
    /// always 0
    pub unk30: u32,
    /// always 0
    pub unk34: u32,
    pub compressed_size: u32,
    /// always 0
    pub unk3_c: u32,
}

/// Represntation of the data after each record header and record file name.
///
/// Some data is not identified at the moment and named "unk*"
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordTrailer {
    pub unk00: u32,
    pub unk04: u32,
    pub unk08: u32,
    pub unk0_c: u32,
    pub unk10: u32,
    pub unk14: u32,
    pub unk18: u32,
    pub unk1_c: u32,
    pub unk20: u32,
    pub unk24: u32,
}

/// Read BFF file header
pub fn read_file_header<R: Read>(reader: &mut R) -> Result<FileHeader, error::BffReadError> {
    let file_header: FileHeader = util::read_struct(reader)?;
    if file_header.magic != FILE_MAGIC {
        let magic = file_header.magic;
        return Err(error::BffReadError::InvalidFileMagic(magic));
    }
    Ok(file_header)
}

/// Read string from stream until NULL.
pub fn read_aligned_string<R: Read>(reader: &mut R) -> Result<String, std::io::Error> {
    let mut result: Vec<u8> = vec![];
    loop {
        let mut data = [0; 8];
        let len = reader.read(&mut data)?;
        if len == 0 {
            return Ok(String::from_utf8_lossy(&result).into());
        }
        for c in data {
            if c == 0 {
                return Ok(String::from_utf8_lossy(&result).into());
            }
            result.push(c);
        }
    }
}

/// Transformed representation of a single fileset record (file or directory entry).
#[derive(Clone, Debug)]
pub struct Record {
    /// Filename
    pub filename: PathBuf,
    /// Compressed file size
    pub compressed_size: u32,
    /// Decompressed file size.
    pub size: u32,
    /// File system mode (rwx...)
    pub mode: Mode,
    /// Owner user ID number of the file
    pub uid: u32,
    /// Owner group ID number of the file
    pub gid: u32,
    /// Last modified date of the file
    pub mdate: NaiveDateTime,
    pub adate: NaiveDateTime,
    /// Position of the file data in the BFF file
    pub file_position: u32,
    /// Magic number of the record
    pub magic: u16,
}

impl From<RecordHeader> for Record {
    fn from(value: RecordHeader) -> Self {
        Record {
            filename: "".into(),
            compressed_size: value.compressed_size,
            size: value.size,
            mode: Mode::from(value.mode),
            uid: value.uid,
            gid: value.gid,
            mdate: DateTime::from_timestamp(value.mtime as i64, 0)
                .map(|dt| dt.naive_local())
                .unwrap_or_else(|| Utc::now().naive_local()),
            adate: DateTime::from_timestamp(value.atime as i64, 0)
                .map(|dt| dt.naive_local())
                .unwrap_or_else(|| Utc::now().naive_local()),
            file_position: 0,
            magic: value.magic,
        }
    }
}

impl Record {
    /// Extract single file from stream to target directory.
    pub fn extract_file<R, P>(
        &self,
        reader: &mut R,
        out_dir: P,
        verbose: bool,
    ) -> Result<(), error::BffError>
    where
        R: Read + Seek,
        P: AsRef<Path>,
    {
        // A normalized target path for the current record file
        let target_path = out_dir.as_ref().join(&self.filename).normalize();

        // Ignore empty file names
        if let Some(path) = target_path.to_str() {
            if path == "" {
                return Ok(());
            }
        }

        if verbose {
            println!("{}", target_path.display());
        }

        match self.mode.file_type() {
            Some(FileType::Directory) => {
                if !target_path.exists() {
                    std::fs::create_dir_all(&target_path)
                        .map_err(|err| error::BffExtractError::IoError(err))?;
                }
            }
            _ => {
                let target_dir = target_path
                    .parent()
                    .ok_or(error::BffError::MissingParentDir(
                        target_path.display().to_string(),
                    ))?;
                if !target_dir.exists() {
                    std::fs::create_dir_all(&target_dir)
                        .map_err(|err| error::BffExtractError::IoError(err))?;
                }

                self.extract_record(reader, &target_path)?;
            }
        }

        set_file_times(
            &target_path,
            FileTime::from_unix_time(self.adate.and_utc().timestamp(), 0),
            FileTime::from_unix_time(self.mdate.and_utc().timestamp(), 0),
        )
        .map_err(|err| error::BffExtractError::IoError(err))?;

        #[cfg(unix)]
        target_path
            .as_path()
            .set_mode(self.mode.mode())
            .map_err(|err| error::BffExtractError::ModeError(Box::new(err)))?;

        Ok(())
    }

    /// Read data record from stream and write to file.
    /// Stream cursor must be at start position of a record.
    pub fn extract_record<R, P>(
        &self,
        reader: &mut R,
        target_path: P,
    ) -> Result<(), error::BffError>
    where
        R: Read + Seek,
        P: AsRef<Path>,
    {
        if self.filename.as_os_str().is_empty() {
            return Err(error::BffReadError::EmptyFilename.into());
        }

        let writer =
            File::create(&target_path).map_err(|err| error::BffExtractError::IoError(err))?;
        let mut writer = BufWriter::new(writer);

        // let mut reader: Box<dyn Read + Seek> = Box::new(reader);
        if self.magic == HUFFMAN_MAGIC {
            let mut reader = HuffmanReader::from(
                reader,
                SeekFrom::Start(self.file_position as u64),
                self.compressed_size as usize,
            )?;
            // huffman::decompress_stream(reader, &mut writer, self.compressed_size as usize)?;
            util::copy_stream(
                &mut reader,
                &mut writer,
                SeekFrom::Start(self.file_position as u64),
                self.compressed_size as usize,
            )
            .map_err(|err| error::BffExtractError::IoError(err))?;
        } else {
            util::copy_stream(
                reader,
                &mut writer,
                SeekFrom::Start(self.file_position as u64),
                self.compressed_size as usize,
            )
            .map_err(|err| error::BffExtractError::IoError(err))?;
        }

        Ok(())
    }
}

/// Iterator struct for reading records of the BFF file.
pub struct RecordReader<'a, R: Read + Seek> {
    reader: &'a mut R,
}

impl<'a, R> RecordReader<'a, R>
where
    R: Read + Seek,
{
    /// Create instance
    pub fn new(reader: &'a mut R) -> Self {
        Self { reader }
    }

    /// Read a single record from BFF stream and transform to a Record.
    fn next_record(&mut self) -> Result<Record, error::BffReadError> {
        let record_header: RecordHeader = util::read_struct(self.reader)?;
        if record_header.unk01 != 0x0b {
            return Err(error::BffReadError::InvalidRecord);
        }
        let magic = record_header.magic;
        if !HEADER_MAGICS.contains(&magic) {
            return Err(error::BffReadError::InvalidRecordMagic(record_header.magic));
        }
        let filename = read_aligned_string(self.reader)?;
        let _record_trailer: RecordTrailer = util::read_struct(self.reader)?;
        let position = self.reader.seek(SeekFrom::Current(0)).unwrap();
        if record_header.size > 0 {
            self.reader
                .seek(SeekFrom::Current(record_header.compressed_size as i64))?;
        }
        let aligned_up = (record_header.compressed_size + 7) & !7;
        self.reader.seek(SeekFrom::Current(
            (aligned_up - record_header.compressed_size) as i64,
        ))?;

        let mut record: Record = record_header.into();

        record.filename = PathBuf::from(filename);
        record.file_position = position as u32;
        Ok(record)
    }
}

impl<'a, R> Iterator for RecordReader<'a, R>
where
    R: Read + Seek,
{
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_record().ok()
    }
}

/// Describes the difference between two files
/// Each value contains a tuple with the content of the left file and the right file
pub enum RecordDiffField {
    Exists(bool, bool),
    Size(u32, u32),
    Mode(Mode, Mode),
    Uid(u32, u32),
    Gid(u32, u32),
    Mdate(NaiveDateTime, NaiveDateTime),
    Magic(u16, u16),
    /// The content of a file in a BFF file has differences.
    Content(RecordDiffContent),
}

/// Differences of two files identified by its file name
pub struct RecordDiff {
    pub filename: PathBuf,
    pub diffs: Vec<RecordDiffField>,
}

impl Display for RecordDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RecordDiffField::*;
        let mut output = String::new();

        // Check if file exists in one side only
        let exists = self.diffs.iter().find(|item| matches!(item, Exists(_, _)));
        let file_diff = match exists {
            Some(Exists(left, _right)) => {
                if *left {
                    "< "
                } else {
                    "> "
                }
            }
            _ => "- ",
        };
        output.push_str(file_diff);

        // Current file name
        output.push_str(&self.filename.display().to_string());
        output.push_str("\n");

        let date_format = "%Y-%m-%d %H:%M:%S";

        // Add all differences
        for diff in self.diffs.iter() {
            let diff_str = match diff {
                Size(left, right) => {
                    format!("  Size:     <  {left}\n             > {right}\n")
                }
                Mode(left, right) => {
                    format!("  Mode:     <  {left}\n             > {right}\n")
                }
                Uid(left, right) => {
                    format!("  UID:      <  {left}\n             > {right}\n")
                }
                Gid(left, right) => {
                    format!("  GID:      <  {left}\n             > {right}\n")
                }
                Mdate(left, right) => format!(
                    "  Modified: <  {}\n             > {}\n",
                    left.format(date_format),
                    right.format(date_format)
                ),
                Magic(left, right) => {
                    format!("  Magic:    <  {left:#01x}\n             > {right:#01x}\n")
                }
                Exists(_, _) => "".into(),
                Content(_) => "".into(),
            };
            output.push_str(&diff_str);
        }
        write!(f, "{}", &output)
    }
}

/// Difference in a file in the BFF file
pub enum RecordDiffContent {
    /// Both files are plaintext files. Provides a diff output.
    Plaintext(String),
    /// At least one file is a binary file. Provides the file position where the first difference occurs.
    Binary(usize),
}

pub fn compare_records(left: &[Record], right: &[Record]) -> Vec<RecordDiff> {
    use RecordDiffField::*;

    let mut left_diffs: Vec<RecordDiff> = left
        .into_iter()
        .filter_map(|l| {
            let r = right.into_iter().find(|r| l.filename == r.filename);
            let mut diffs = vec![];
            if let Some(r) = r {
                // In both lists but has differences
                if l.size != r.size {
                    diffs.push(Size(l.size, r.size));
                }
                if l.mode != r.mode {
                    diffs.push(Mode(l.mode.clone(), r.mode.clone()));
                }
                if l.uid != r.uid {
                    diffs.push(Uid(l.uid, r.uid));
                }
                if l.gid != r.gid {
                    diffs.push(Gid(l.gid, r.gid));
                }
                if l.mdate != r.mdate {
                    diffs.push(Mdate(l.mdate, r.mdate));
                }
                if l.magic != r.magic {
                    diffs.push(Magic(l.magic, r.magic));
                }
            } else {
                // In left list only
                diffs.push(Exists(true, false));
            }
            if diffs.len() > 0 {
                return Some(RecordDiff {
                    filename: l.filename.clone(),
                    diffs,
                });
            }
            None
        })
        .collect();

    let right_diffs: Vec<RecordDiff> = right
        .into_iter()
        .filter_map(|r| {
            let l = left.into_iter().find(|l| l.filename == r.filename);
            let mut diffs = vec![];
            if let None = l {
                // In right list only
                diffs.push(Exists(false, true));
            }
            if diffs.len() > 0 {
                return Some(RecordDiff {
                    filename: r.filename.clone(),
                    diffs,
                });
            }
            None
        })
        .collect();

    left_diffs.extend(right_diffs);
    left_diffs
}

/// Creates a Iterator to read all records.
pub fn get_record_listing<R: Read + Seek>(reader: &mut R) -> impl Iterator<Item = Record> + '_ {
    let record_reader = RecordReader::new(reader);
    record_reader
}

pub(crate) fn open_bff_file<P: AsRef<Path>>(
    filename: P,
) -> Result<(impl Read + Seek, FileHeader), BffError> {
    let reader = File::open(filename).map_err(|err| BffReadError::IoError(err))?;
    if reader.metadata().unwrap().len() > 0xffffffff {
        return Err(BffReadError::FileToBig.into());
    }
    let mut reader = BufReader::new(reader);
    let header = read_file_header(&mut reader)?;
    Ok((reader, header))
}

struct RecordContentReader {}

impl Read for RecordContentReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}
