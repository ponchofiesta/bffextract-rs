//! Reading an BFF archive

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
#[cfg(unix)]
use std::os::unix::fs::chown;

use crate::{
    attribute,
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
    make_record_reader_raw(reader, record, false)
}

/// Create a reader for contents of a record
/// 
/// Set `raw = true` to read the bytes as is without decoding huffman encoded data.
fn make_record_reader_raw<'a, R: Read + Seek>(
    reader: &'a mut R,
    record: &Record,
    raw: bool,
) -> Result<Option<RecordReader<'a>>> {
    match record.mode().file_type() {
        Some(t) if t.is_regular_file() => {
            reader.seek(SeekFrom::Start(record.file_position() as u64))?;
            let take = (reader as &mut dyn Read).take(record.compressed_size() as u64);
            let record_reader = if record.magic() == HUFFMAN_MAGIC && !raw {
                RecordReader::Huffman(HuffmanDecoder::new(take)?)
            } else {
                RecordReader::Raw(take)
            };
            Ok(Some(record_reader))
        }
        _ => Err(Error::UnsupportedFileType),
    }
}

fn set_file_attributes<P: AsRef<Path>>(path: P, record: &Record, attributes: u8) -> io::Result<()> {
    if attributes & attribute::ATTRIBUTE_TIMESTAMPS > 0 {
        set_file_times(
            &path,
            FileTime::from_unix_time(record.adate().and_utc().timestamp(), 0),
            FileTime::from_unix_time(record.mdate().and_utc().timestamp(), 0),
        )?;
    }
    #[cfg(unix)]
    {
        if attributes & attribute::ATTRIBUTE_OWNERS > 0 {
            chown(&path, Some(record.uid()), Some(record.gid()))?;
        }
        if attributes & attribute::ATTRIBUTE_PERMISSIONS > 0 {
            path.as_ref()
                .set_mode(record.mode().mode())
                .map_err(|err| io::Error::other(err))?;
        }
    }
    Ok(())
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

    /// Creates a raw reader for a specific file without decoding.
    pub fn raw_file<'a, P: AsRef<Path>>(&'a mut self, filename: P) -> Result<Option<RecordReader<'a>>> {
        let record = self
            .record_by_filename(&filename)
            .ok_or(Error::FileNotFound)?
            .clone();
        make_record_reader_raw(&mut self.reader, &record, true)
    }

    /// Extract a single file of the archive by filename.
    pub fn extract_file_by_name<P: AsRef<Path>, D: AsRef<Path>>(
        &mut self,
        filename: P,
        destination: D,
    ) -> Result<()> {
        self.extract_file_by_name_with_attr(filename, destination, attribute::ATTRIBUTE_DEFAULT)
    }

    /// Extract a single file of the archive by filename and set file modes to be extracted.
    pub fn extract_file_by_name_with_attr<P: AsRef<Path>, D: AsRef<Path>>(
        &mut self,
        filename: P,
        destination: D,
        attributes: u8,
    ) -> Result<()> {
        let record = self
            .record_by_filename(&filename)
            .ok_or(Error::FileNotFound)?
            .clone();
        self.extract_file_with_attr(&record, destination, attributes)
    }

    /// Extract a single file of the archive.
    pub fn extract_file<D: AsRef<Path>>(
        &mut self,
        record: &Record,
        destination: D,
    ) -> Result<()> {
        self.extract_file_with_attr(record, destination, attribute::ATTRIBUTE_DEFAULT)
    }

    /// Extract a single file of the archive and set file modes to be extracted
    pub fn extract_file_with_attr<D: AsRef<Path>>(
        &mut self,
        record: &Record,
        destination: D,
        attributes: u8,
    ) -> Result<()> {
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

        set_file_attributes(&destination, record, attributes)?;

        Ok(())
    }

    /// Extract the whole archive to a target directory and filter the files by a callback function.
    pub fn extract<'a, P: AsRef<Path>>(&'a mut self, destination: P) -> Result<()> {
        self.extract_when(destination, |_| true)
    }

    /// Extract the whole archive to a target directory and filter the files by a callback function.
    ///
    /// `when` is a callback function returning `true` to extract the record or `false` to skip the record.
    pub fn extract_when<'a, P, C>(
        &'a mut self,
        destination: P,
        when: C,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        C: Fn(&Record) -> bool,
    {
        self.extract_when_with_attr(destination, attribute::ATTRIBUTE_DEFAULT, when)
    }

    /// Extract the whole archive to a target directory and filter the files by a callback function and set file modes to be extracted.
    ///
    /// `when` is a callback function returning `true` to extract the record or `false` to skip the record.
    pub fn extract_when_with_attr<'a, P, C>(
        &'a mut self,
        destination: P,
        attributes: u8,
        when: C,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        C: Fn(&Record) -> bool,
    {
        let records: Vec<_> = self.records.iter().cloned().collect();
        for record in records {
            if when(&record) {
                let target_path = destination.as_ref().join(record.filename()).normalize();
                match self.extract_file_with_attr(&record, &target_path, attributes) {
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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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

#[cfg(test)]
mod tests {
    use crate::bff;

    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::{fs, io::Result};
    use tempfile::tempdir;

    fn open_bff_file<P: AsRef<Path>>(filename: P) -> Result<impl Read + Seek> {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("../resources/test");
        File::open(dir.join(filename))
    }

    #[test]
    fn test_read_file_header() {
        let mut file = open_bff_file("test.bff").unwrap();

        let result = read_file_header(&mut file);

        assert!(result.is_ok());
        let header = result.unwrap();
        let magic = header.magic;
        assert_eq!(magic, FILE_MAGIC);
    }

    #[test]
    fn test_read_next_record() {
        let mut file = open_bff_file("test.bff").unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();

        let result = read_next_record(&mut file);

        assert!(result.is_ok());
        let record = result.unwrap();
        assert!(record.is_some());
        let record = record.unwrap();
        let magic = record.header.magic;
        assert!(HEADER_MAGICS.contains(&magic));
    }

    #[test]
    fn test_read_records() {
        let mut file = open_bff_file("test.bff").unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();

        let result = read_records(&mut file);

        assert!(result.is_ok());
        let records = result.unwrap();
        assert!(!records.is_empty());
        assert_eq!(records.len(), 4);
    }

    #[test]
    fn test_record_by_filename() {
        let mut file = open_bff_file("test.bff").unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();

        let records = read_records(&mut file).unwrap();

        let filename = Path::new("backup/file.txt");
        let record = record_by_filename(&records, filename);

        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.filename(), filename);
    }

    #[test]
    fn test_extract_file() {
        let mut file = open_bff_file("test.bff").unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();

        let temp_dir = tempdir().unwrap();
        let dest_path = temp_dir.path().join("extracted_file.txt");

        let records = read_records(&mut file).unwrap();

        let mut reader = make_record_reader(&mut file, &records[1]).unwrap().unwrap();

        let result = extract_file(&mut reader, &dest_path);

        assert!(result.is_ok());
        assert!(dest_path.exists());
    }

    #[test]
    fn test_make_record_reader_unsupported_filetype() {
        let mut file = open_bff_file("test.bff").unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();

        let records = read_records(&mut file).unwrap();

        let result = make_record_reader(&mut file, &records[0]);

        assert!(result.is_err());
    }

    #[test]
    fn test_set_file_attributes_timestamps() {
        let record_header = bff::RecordHeader {
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: 1_600_000_000,
            atime: 1_600_000_000,
            ..Default::default()
        };
        let record = Record {
            data: record_header.into(),
            header: record_header,
            trailer: Default::default(),
        };
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("mock_file.txt");

        // Create a mock file to set attributes on
        File::create(&file_path).unwrap();

        // Set the attributes
        let result = set_file_attributes(
            &file_path,
            &record,
            attribute::ATTRIBUTE_TIMESTAMPS,
        );
        assert!(result.is_ok());

        // Verify the timestamps
        let metadata = fs::metadata(&file_path).unwrap();
        let mtime = FileTime::from_last_modification_time(&metadata);
        let atime = FileTime::from_last_access_time(&metadata);
        assert_eq!(mtime.unix_seconds(), 1_600_000_000);
        assert_eq!(atime.unix_seconds(), 1_600_000_000);

    }

    #[cfg(unix)]
    #[test]
    fn test_set_file_attributes_timestamp_and_mode() {
        let record_header = bff::RecordHeader {
            mode: 0o644,
            mtime: 1_600_000_000,
            atime: 1_600_000_000,
            ..Default::default()
        };
        let record = Record {
            data: record_header.into(),
            header: record_header,
            trailer: Default::default(),
        };
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("mock_file.txt");

        // Create a mock file to set attributes on
        File::create(&file_path).unwrap();

        // Set the attributes
        let result = set_file_attributes(
            &file_path,
            &record,
            attribute::ATTRIBUTE_TIMESTAMPS
                | attribute::ATTRIBUTE_PERMISSIONS,
        );
        assert!(result.is_ok());

        // Verify the timestamps
        let metadata = fs::metadata(&file_path).unwrap();
        let mtime = FileTime::from_last_modification_time(&metadata);
        let atime = FileTime::from_last_access_time(&metadata);
        assert_eq!(mtime.unix_seconds(), 1_600_000_000);
        assert_eq!(atime.unix_seconds(), 1_600_000_000);

        // Verify the permissions
        assert_eq!(metadata.mode() & 0o777, 0o644);
    }

    #[test]
    fn test_archive_creation() {
        let file = open_bff_file("test.bff").unwrap();

        let archive = Archive::new(file);

        assert!(archive.is_ok());
        let archive = archive.unwrap();
        assert!(!archive.records().is_empty());
    }

    #[test]
    fn test_extract_file_by_name() {
        let file = open_bff_file("test.bff").unwrap();

        let temp_dir = tempdir().unwrap();
        let dest_path = temp_dir.path().join("extracted_file.txt");

        let mut archive = Archive::new(file).unwrap();
        let result =
            archive.extract_file_by_name_with_attr("backup/file.txt", &dest_path, attribute::ATTRIBUTE_NONE);

        assert!(result.is_ok());
        assert!(dest_path.exists());
    }
}
