use chrono::prelude::*;
use file_mode::Mode;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom};
use std::path::Path;

use crate::{error, huffman, util};

pub const FILE_MAGIC: u32 = 0xea6b0009; //0x09006BEA;
pub const HUFFMAN_MAGIC: u16 = 0xEA6C;
pub const HEADER_MAGICS: [u16; 3] = [0xEA6B, HUFFMAN_MAGIC, 0xEA6D];

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FileHeader {
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
    pub username: [u8; 8],
    pub unk3_c: u32,
    pub unk40: u32,
    pub unk44: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordHeader {
    pub unk00: u16,
    pub magic: u16,
    pub unk04: u32,
    pub unk08: u32, // maybe directory ID or counter, always 0 for files
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub atime: u32,
    pub mtime: u32,
    pub time24: u32,
    pub unk28: u32,  // always last bits: 1010 (10)
    pub unk2_c: u32, // always last bits: 111 (7)
    pub unk30: u32,  // always 0
    pub unk34: u32,  // always 0
    pub compressed_size: u32,
    pub unk3_c: u32, // always 0
}

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

/// Read date from stream and write to file.
pub fn extract_record<R: Read, P: AsRef<Path>>(
    reader: &mut R,
    name: &str,
    size: usize,
    decompress: bool,
    target_path: P,
) -> Result<(), error::BffError> {
    if name.is_empty() {
        return Err(error::BffReadError::EmptyFilename.into());
    }

    let writer = File::create(&target_path).map_err(|err| error::BffExtractError::IoError(err))?;
    let mut writer = BufWriter::new(writer);
    if decompress {
        huffman::decompress_stream(reader, &mut writer, size)?;
    } else {
        util::copy_stream(reader, &mut writer, size)
            .map_err(|err| error::BffExtractError::IoError(err))?;
    }
    Ok(())
}

/// transformed representation of a single fileset record (file or directory entry).
#[derive(Debug)]
pub struct Record {
    pub filename: String,
    pub compressed_size: u32,
    pub size: u32,
    pub mode: Mode,
    pub uid: u32,
    pub gid: u32,
    pub mdate: NaiveDateTime,
    pub adate: NaiveDateTime,
    pub file_position: u32,
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
        }
    }
}

pub struct RecordReader<'a, R: Read + Seek> {
    reader: &'a mut R,
}

impl<'a, R> RecordReader<'a, R>
where
    R: Read + Seek,
{
    pub fn new(reader: &'a mut R) -> Self {
        Self { reader }
    }

    /// Read a single record from BFF stream and transform to a Record.
    fn next_record(&mut self) -> Result<Record, error::BffReadError> {
        let record_header: RecordHeader = util::read_struct(self.reader)?;
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

pub fn get_record_listing<R: Read + Seek>(reader: &mut R) -> impl Iterator<Item = Record> + '_ {
    let record_reader = RecordReader::new(reader);
    record_reader
}
