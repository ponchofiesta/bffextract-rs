use crate::{error, huffman, util};
use chrono::prelude::*;
use file_mode::{FileType, Mode};
use filetime::{set_file_times, FileTime};
use normalize_path::NormalizePath;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom};
use std::path::Path;

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

/// Read data record from stream and write to file.
/// Stream cursor must be at start position of a record.
pub fn extract_record<R: Read + Seek, P: AsRef<Path>>(
    reader: &mut R,
    record: &Record,
    target_path: P,
) -> Result<(), error::BffError> {
    if record.filename.is_empty() {
        return Err(error::BffReadError::EmptyFilename.into());
    }

    let writer = File::create(&target_path).map_err(|err| error::BffExtractError::IoError(err))?;
    let mut writer = BufWriter::new(writer);
    reader
        .seek(SeekFrom::Start(record.file_position as u64))
        .unwrap();

    if record.magic == HUFFMAN_MAGIC {
        huffman::decompress_stream(reader, &mut writer, record.compressed_size as usize)?;
    } else {
        util::copy_stream(reader, &mut writer, record.compressed_size as usize)
            .map_err(|err| error::BffExtractError::IoError(err))?;
    }
    Ok(())
}

/// Transformed representation of a single fileset record (file or directory entry).
#[derive(Debug)]
pub struct Record {
    /// Filename
    pub filename: String,
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
            mdate: NaiveDateTime::from_timestamp_opt(value.mtime as i64, 0)
                .unwrap_or_else(|| Utc::now().naive_local()),
            adate: NaiveDateTime::from_timestamp_opt(value.atime as i64, 0)
                .unwrap_or_else(|| Utc::now().naive_local()),
            file_position: 0,
            magic: value.magic,
        }
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
        record.filename = filename;
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

/// Creates a Iterator to read all records.
pub fn get_record_listing<R: Read + Seek>(reader: &mut R) -> impl Iterator<Item = Record> + '_ {
    let record_reader = RecordReader::new(reader);
    record_reader
}

/// Extract single file from stream to target directory.
pub fn extract_file<R: Read + Seek, P: AsRef<Path>>(
    reader: &mut R,
    record: Record,
    out_dir: P,
    verbose: bool,
) -> Result<(), error::BffError> {
    // A normalized target path for the current record file
    let target_path = out_dir.as_ref().join(&record.filename).normalize();

    // Ignore empty file names
    if let Some(path) = target_path.to_str() {
        if path == "" {
            return Ok(());
        }
    }

    if verbose {
        println!("{}", target_path.display());
    }

    match record.mode.file_type() {
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

            extract_record(reader, &record, &target_path)?;
        }
    }

    set_file_times(
        &target_path,
        FileTime::from_unix_time(record.adate.timestamp(), 0),
        FileTime::from_unix_time(record.mdate.timestamp(), 0),
    )
    .map_err(|err| error::BffExtractError::IoError(err))?;

    #[cfg(unix)]
    target_path
        .as_path()
        .set_mode(record.mode.mode())
        .map_err(|err| error::BffExtractError::ModeError(Box::new(err)))?;

    Ok(())
}
