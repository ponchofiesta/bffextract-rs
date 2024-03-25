use std::{
    fs::File,
    io::{self, copy, BufWriter, Read, Seek, SeekFrom, Take},
    path::{Path, PathBuf},
};

use chrono::{DateTime, NaiveDateTime, Utc};
use file_mode::Mode;
#[cfg(unix)]
use file_mode::ModePath;
use filetime::{set_file_times, FileTime};
use normalize_path::NormalizePath;

use crate::{
    bff::{
        read_aligned_string, FileHeader, RecordHeader, RecordTrailer, FILE_MAGIC, HEADER_MAGICS,
        HUFFMAN_MAGIC,
    },
    huffman::HuffmanDecoder,
    util::{self, create_dir_all},
};
use crate::{Error, Result};

/// Read BFF [FileHeader] from the reader
fn read_file_header<R: Read>(reader: &mut R) -> Result<FileHeader> {
    let file_header: FileHeader = util::read_struct(reader)?;
    if file_header.magic != FILE_MAGIC {
        let magic = file_header.magic;
        return Err(Error::InvalidFileMagic(magic));
    }
    Ok(file_header)
}

/// Read next [Record] from the reader
fn read_next_record<R: Read + Seek>(reader: &mut R) -> Result<Option<Record>> {
    let record_header: RecordHeader = util::read_struct(reader)?;
    if record_header.unk01 != 0x0b {
        return Err(Error::InvalidRecord);
    }
    let magic = record_header.magic;
    if !HEADER_MAGICS.contains(&magic) {
        return Err(Error::InvalidRecordMagic(record_header.magic));
    }
    let filename = read_aligned_string(reader)?;
    let record_trailer: RecordTrailer = util::read_struct(reader)?;
    let position = reader.stream_position()?;
    if record_header.size > 0 {
        reader.seek(SeekFrom::Current(record_header.compressed_size as i64))?;
    }
    let aligned_up = (record_header.compressed_size + 7) & !7;
    reader.seek(SeekFrom::Current(
        (aligned_up - record_header.compressed_size) as i64,
    ))?;

    let mut record_data: RecordData = record_header.into();
    record_data.filename = PathBuf::from(filename);
    record_data.file_position = position as u32;

    let record = Record {
        data: record_data,
        header: record_header,
        trailer: record_trailer,
    };
    Ok(Some(record))
}

/// Read all [Record]s from the reader
fn read_records<R: Read + Seek>(reader: &mut R) -> Result<Vec<Record>> {
    let mut records = vec![];
    loop {
        match read_next_record(reader) {
            Ok(record) => match record {
                Some(record) => records.push(record),
                None => break,
            },
            Err(e) => match e {
                Error::InvalidRecord => (),
                // Hopefully not unexpected EOF
                Error::IoError(io_e) if io_e.kind() == io::ErrorKind::UnexpectedEof => break,
                Error::InvalidRecordMagic(_magic) => (),
                _ => return Err(e),
            },
        }
    }
    Ok(records)
}

/// Find a [Record] by its filename
fn record_by_filename<'a, P: AsRef<Path>>(
    records: &'a [Record],
    filename: P,
) -> Option<&'a Record> {
    records
        .iter()
        .find(|record| record.filename() == filename.as_ref())
}

/// Extract a single file to destination folder.
fn extract_file<R: Read, D: AsRef<Path>>(reader: &mut R, destination: D) -> Result<()> {
    let writer = File::create(destination)?;
    let mut writer = BufWriter::new(writer);
    match copy(reader, &mut writer) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Create a reader for contents of a record
fn make_record_reader<'a, R: Read + Seek>(
    reader: &'a mut R,
    record: &Record,
) -> Result<Option<RecordReader<'a>>> {
    match record.mode().file_type() {
        Some(t) if t.is_regular_file() => {
            reader.seek(SeekFrom::Start(record.file_position() as u64))?;
            let take = (reader as &mut dyn Read).take(record.compressed_size() as u64);
            let record_reader = if record.magic() == HUFFMAN_MAGIC {
                RecordReader::Huffman(HuffmanDecoder::new(take)?)
            } else {
                RecordReader::Raw(take)
            };
            Ok(Some(record_reader))
        }
        _ => Err(Error::UnsupportedFileType),
    }
}

/// A BFF archive
pub struct Archive<R> {
    reader: R,
    header: FileHeader,
    records_start_pos: u64,
    records: Vec<Record>,
}

impl<R: Read + Seek> Archive<R> {
    /// Creates a new Archive instance and reads the file informations and info about all records.
    pub fn new(mut reader: R) -> Result<Self> {
        let header = read_file_header(&mut reader)?;
        let records_start_pos = reader.stream_position()?;
        let records = read_records(&mut reader)?;
        let archive = Self {
            reader,
            header,
            records_start_pos,
            records,
        };
        Ok(archive)
    }

    /// Returns the archive records
    pub fn records(&self) -> Vec<&Record> {
        self.records.iter().collect()
    }

    /// Returns the [FileHeader] of the archive
    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// Returns the position of the first record in the BFF file
    pub fn records_start_pos(&self) -> u64 {
        self.records_start_pos
    }

    /// Finds a [Record] by its filename. Return [None] if the filename wasn't found.
    pub fn record_by_filename<P: AsRef<Path>>(&self, filename: P) -> Option<&Record> {
        record_by_filename(&self.records, filename)
    }

    /// Creates a reader for a specific file.
    pub fn file<'a, P: AsRef<Path>>(&'a mut self, filename: P) -> Result<Option<RecordReader<'a>>> {
        let record = self
            .record_by_filename(&filename)
            .ok_or(Error::FileNotFound)?
            .clone();
        make_record_reader(&mut self.reader, &record)
    }

    /// Extract a single file of the archive by filename.
    pub fn extract_file_by_name<P: AsRef<Path>, D: AsRef<Path>>(
        &mut self,
        filename: P,
        destination: D,
    ) -> Result<()> {
        let record = self
            .record_by_filename(&filename)
            .ok_or(Error::FileNotFound)?
            .clone();
        self.extract_file(&record, destination)
    }

    /// Extract a single file of the archive.
    pub fn extract_file<D: AsRef<Path>>(&mut self, record: &Record, destination: D) -> Result<()> {
        match record.mode().file_type() {
            // Record contains a directory
            Some(t) if t.is_directory() => Ok(create_dir_all(&destination)?),
            // Record cotnains a file
            Some(t) if t.is_regular_file() => {
                let parent = destination
                    .as_ref()
                    .parent()
                    .ok_or(Error::MissingParentDir(
                        destination.as_ref().to_string_lossy().to_string(),
                    ))?;
                create_dir_all(parent)?;
                let mut reader =
                    make_record_reader(&mut self.reader, &record)?.ok_or(Error::FileNotFound)?;
                extract_file(&mut reader, &destination)
            }
            // Record contains something else -> unsupported
            _ => Err(Error::UnsupportedFileType),
        }?;

        set_file_times(
            &destination,
            FileTime::from_unix_time(record.adate().and_utc().timestamp(), 0),
            FileTime::from_unix_time(record.mdate().and_utc().timestamp(), 0),
        )
        .map_err(Error::IoError)?;

        #[cfg(unix)]
        destination
            .as_ref()
            .set_mode(record.mode().mode())
            .map_err(|err| Error::ModeError(Box::new(err)))?;

        Ok(())
    }

    /// Extract the whole archive to a target directory and filter the files by a callback function.
    pub fn extract<'a, P: AsRef<Path>>(&'a mut self, destination: P) -> Result<()> {
        self.extract_when(destination, |_| true)
    }

    /// Extract the whole archive to a target directory and filter the files by a callback function.
    ///
    /// `when` is a callback function returning `true` to extract the record or `false` to skip the record.
    pub fn extract_when<'a, P, C>(&'a mut self, destination: P, when: C) -> Result<()>
    where
        P: AsRef<Path>,
        C: Fn(&Record) -> bool,
    {
        let records: Vec<_> = self.records.iter().cloned().collect();
        for record in records {
            if when(&record) {
                let target_path = destination.as_ref().join(record.filename()).normalize();
                match self.extract_file(&record, &target_path) {
                    Err(e) => match e {
                        Error::EmptyFilename => eprintln!("{e}"),
                        Error::ModeError(ref _mode_error) => eprintln!("{e}"),
                        Error::MissingParentDir(ref _path) => eprintln!("{e}"),
                        _ => return Err(e),
                    },
                    _ => (),
                }
            }
        }
        Ok(())
    }
}

/// A reader to handle different file types
pub enum RecordReader<'a> {
    Raw(Take<&'a mut dyn Read>),
    Huffman(HuffmanDecoder<Take<&'a mut dyn Read>>),
}

impl<'a> Read for RecordReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            RecordReader::Raw(r) => r.read(buf),
            RecordReader::Huffman(r) => r.read(buf),
        }
    }
}

/// Container for all record data
#[derive(Clone)]
pub struct Record {
    data: RecordData,
    header: RecordHeader,
    trailer: RecordTrailer,
}

impl Record {
    pub fn filename(&self) -> &Path {
        &self.data.filename
    }
    pub fn compressed_size(&self) -> u32 {
        self.data.compressed_size
    }
    pub fn size(&self) -> u32 {
        self.data.size
    }
    pub fn mode(&self) -> &Mode {
        &self.data.mode
    }
    pub fn uid(&self) -> u32 {
        self.data.uid
    }
    pub fn gid(&self) -> u32 {
        self.data.gid
    }
    pub fn mdate(&self) -> &NaiveDateTime {
        &self.data.mdate
    }
    pub fn adate(&self) -> &NaiveDateTime {
        &self.data.adate
    }
    pub fn file_position(&self) -> u32 {
        self.data.file_position
    }
    pub fn magic(&self) -> u16 {
        self.data.magic
    }

    pub fn header(&self) -> &RecordHeader {
        &self.header
    }
    pub fn trailer(&self) -> &RecordTrailer {
        &self.trailer
    }
}

/// Transformed representation of a single fileset record (file or directory entry).
#[derive(Clone)]
pub struct RecordData {
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

impl From<RecordHeader> for RecordData {
    fn from(value: RecordHeader) -> Self {
        RecordData {
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
