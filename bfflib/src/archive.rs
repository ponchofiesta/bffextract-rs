//! Reading an BFF archive

use std::{
    fs::File,
    io::{self, copy, BufWriter, Read, Seek, SeekFrom, Take},
    path::{Path, PathBuf},
};

use chrono::{DateTime, NaiveDateTime, Utc};
#[cfg(unix)]
use file_mode::ModePath;
use file_mode::{FileType, Mode};
use filetime::{set_file_times, FileTime};
use normalize_path::NormalizePath;
#[cfg(unix)]
use std::os::unix::fs::{chown, symlink};

use crate::{
    attribute,
    bff::{
        read_aligned_string, FileHeader, RecordHeader, RecordTrailer, FILE_MAGIC, HEADER_MAGICS,
        HUFFMAN_MAGIC, S_IXACL, TRAILER_INLINE_ACL_BYTES,
    },
    huffman::HuffmanDecoder,
    util::{self, create_dir_all, create_parent_dir_all},
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

/// Parse the raw ACL payload bytes into base permissions and named ACL entries.
///
/// Layout (little-endian unless noted):
/// - `reserved`      u16 LE  (ignored)
/// - `owner_perm`    u16 LE  (rwx bits for owner)
/// - `group_perm`    u16 LE  (rwx bits for group)
/// - `everyone_perm` u16 LE  (rwx bits for everyone)
/// - `(num_entries - 3)` compact ACEs, each 12 bytes:
///     - `ace_len`        u16 LE  (total ACE byte length, typically 12)
///     - `access_word`    u16 LE  (bit 15 = allow/deny, bits 0-2 = rwx)
///     - `id_block_len`   u16 LE  (typically 8, ignored)
///     - `principal_type` u16 LE  (1 = user, 2 = group)
///     - `principal_id`   u32 BE  (UID or GID)
fn parse_acl_payload(buf: &[u8], num_entries: u32) -> (u16, u16, u16, Vec<AclEntry>) {
    if buf.len() < 8 {
        return (0, 0, 0, vec![]);
    }
    // First 8 bytes: 4 x u16 LE (reserved, owner, group, everyone)
    let owner_perm = u16::from_le_bytes([buf[2], buf[3]]);
    let group_perm = u16::from_le_bytes([buf[4], buf[5]]);
    let everyone_perm = u16::from_le_bytes([buf[6], buf[7]]);

    let ext_count = (num_entries as usize).saturating_sub(3);
    let mut entries = Vec::with_capacity(ext_count);
    let mut pos = 8usize;

    for _ in 0..ext_count {
        if pos + 12 > buf.len() {
            break;
        }
        let ace_len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        let access_word = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]);
        // buf[pos+4..pos+6] = id_block_len, not needed
        let principal_type_raw = u16::from_le_bytes([buf[pos + 6], buf[pos + 7]]);
        let principal_id =
            u32::from_be_bytes([buf[pos + 8], buf[pos + 9], buf[pos + 10], buf[pos + 11]]);

        let principal_type = match principal_type_raw {
            1 => AclPrincipalType::User,
            2 => AclPrincipalType::Group,
            other => AclPrincipalType::Unknown(other),
        };

        entries.push(AclEntry {
            principal_type,
            principal_id,
            access_word,
        });

        // Advance by ace_len; guard against malformed data
        pos += ace_len.max(12);
    }

    (owner_perm, group_perm, everyone_perm, entries)
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

    // Record is a symlink and we need to read the symlink target too
    let mut symlink = None;
    if record_header.mode & 0xF000 == 0xA000 {
        symlink = Some(read_aligned_string(reader)?);
    }

    let record_trailer: RecordTrailer = util::read_struct(reader)?;

    // The ACL payload is partially embedded inside the trailer struct itself:
    // `acl_payload_bytes` holds the first TRAILER_INLINE_ACL_BYTES (24) bytes.
    // When acl_len > 24, the remaining bytes follow immediately in the stream.
    // This payload must be fully consumed before capturing `stream_position` so
    // that `file_position` points at the actual compressed file data.
    let acl_payload: Option<Vec<u8>> =
        if record_header.mode & S_IXACL > 0 && record_trailer.acl_len > 0 {
            let acl_len = record_trailer.acl_len as usize;
            let inline = &record_trailer.acl_payload_bytes[..acl_len.min(TRAILER_INLINE_ACL_BYTES)];
            let mut payload = inline.to_vec();
            if acl_len > TRAILER_INLINE_ACL_BYTES {
                let extra = acl_len - TRAILER_INLINE_ACL_BYTES;
                let mut buf = vec![0u8; extra];
                reader.read_exact(&mut buf)?;
                payload.extend_from_slice(&buf);
            }
            Some(payload)
        } else {
            None
        };

    let position = reader.stream_position()?;
    if record_header.size > 0 {
        reader.seek(SeekFrom::Current(record_header.compressed_size as i64))?;
    }
    let aligned_up = (record_header.compressed_size + 7) & !7;
    reader.seek(SeekFrom::Current(
        (aligned_up - record_header.compressed_size) as i64,
    ))?;

    let mut record_data = RecordData::new(record_header, record_trailer, acl_payload);
    record_data.filename = PathBuf::from(filename);
    if let Some(symlink) = symlink {
        record_data.symlink = Some(PathBuf::from(symlink));
    }
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
        _ => Err(Error::UnsupportedFileType(format!(
            "{:?}",
            record.mode().file_type()
        ))),
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
    pub fn raw_file<'a, P: AsRef<Path>>(
        &'a mut self,
        filename: P,
    ) -> Result<Option<RecordReader<'a>>> {
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
    pub fn extract_file<D: AsRef<Path>>(&mut self, record: &Record, destination: D) -> Result<()> {
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
                create_parent_dir_all(&destination)?;
                let mut reader =
                    make_record_reader(&mut self.reader, &record)?.ok_or(Error::FileNotFound)?;
                extract_file(&mut reader, &destination)
            }
            // Record contains a symbolic link
            #[cfg(unix)]
            Some(t) if t.is_symbolic_link() => {
                create_parent_dir_all(&destination)?;
                symlink(&destination, record.symlink().unwrap())?;
                Ok(())
            }
            Some(t) if self.is_unsupported_filetype(t) => {
                create_parent_dir_all(&destination)?;
                eprintln!(
                    "{}: Unsupported file type {:?}. Will create an empty file instead.",
                    record.filename().display(),
                    record.mode().file_type()
                );
                File::create(&destination)?;
                Ok(())
            }
            // Record contains something else -> unsupported
            _ => Err(Error::UnsupportedFileType(format!(
                "{:?}",
                record.mode().file_type()
            ))),
        }?;

        set_file_attributes(&destination, record, attributes)?;

        Ok(())
    }

    fn is_unsupported_filetype(&self, filetype: FileType) -> bool {
        let unsup = filetype.is_block_device()
            || filetype.is_character_device()
            || filetype.is_fifo()
            || filetype.is_socket();

        #[cfg(windows)]
        let unsup = unsup || filetype.is_symbolic_link();

        unsup
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
                    Err(e) => {
                        eprintln!("{}: {e}", record.filename().display());
                    }
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
    pub fn symlink(&self) -> Option<&Path> {
        self.data.symlink.as_ref().map(|pb| pb.as_ref())
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
    pub fn acl(&self) -> Option<&AclData> {
        self.data.acl.as_ref()
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
    pub symlink: Option<PathBuf>,
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
    /// Access control list
    pub acl: Option<AclData>,
}

impl RecordData {
    pub fn new(header: RecordHeader, trailer: RecordTrailer, acl_payload: Option<Vec<u8>>) -> Self {
        let acl = if header.mode & S_IXACL > 0 {
            let (owner_perm, group_perm, everyone_perm, entries) =
                if let Some(buf) = acl_payload {
                    parse_acl_payload(&buf, trailer.num_entries)
                } else {
                    (0, 0, 0, vec![])
                };
            Some(AclData {
                num_entries: trailer.num_entries,
                version: trailer.version,
                acl_len: trailer.acl_len,
                acl_mode: trailer.acl_mode,
                owner_perm,
                group_perm,
                everyone_perm,
                entries,
            })
        } else {
            None
        };
        Self {
            filename: PathBuf::new(),
            symlink: None,
            compressed_size: header.compressed_size,
            size: header.size,
            mode: Mode::from(header.mode),
            uid: header.uid,
            gid: header.gid,
            mdate: DateTime::from_timestamp(header.mtime as i64, 0)
                .map(|dt| dt.naive_local())
                .unwrap_or_else(|| Utc::now().naive_local()),
            adate: DateTime::from_timestamp(header.atime as i64, 0)
                .map(|dt| dt.naive_local())
                .unwrap_or_else(|| Utc::now().naive_local()),
            file_position: 0,
            magic: header.magic,
            acl,
        }
    }
}

/// Principal type for an ACL entry.
#[derive(Clone, Debug, PartialEq)]
pub enum AclPrincipalType {
    User,
    Group,
    Unknown(u16),
}

/// A single named ACL entry (named user or named group).
///
/// Corresponds to a compact ACE in the BFF ACL payload.
#[derive(Clone, Debug)]
pub struct AclEntry {
    /// Whether this entry applies to a user or a group.
    pub principal_type: AclPrincipalType,
    /// UID (for [`AclPrincipalType::User`]) or GID (for [`AclPrincipalType::Group`]).
    pub principal_id: u32,
    /// Raw access word from the BFF compact ACE.
    /// Bit 15 = allow (1) / deny (0). Bits 2–0 = rwx.
    pub access_word: u16,
}

impl AclEntry {
    /// Returns `true` if this entry grants access (allow ACE).
    pub fn is_allow(&self) -> bool {
        self.access_word & 0x8000 != 0
    }

    /// Returns the rwx permission bits (0–7).
    pub fn rwx(&self) -> u8 {
        (self.access_word & 0x7) as u8
    }
}

#[derive(Clone, Debug)]
pub struct AclData {
    /// Number of ACL entries, including the 3 base identities (owner, group, everyone).
    pub num_entries: u32,
    /// Access control list version.
    pub version: u32,
    /// Byte length of the ACL payload that follows the record trailer.
    pub acl_len: u32,
    /// ACL mode flags (contains [`S_IXACL`] when an ACL is present).
    pub acl_mode: u32,
    /// Owner permissions as rwx bits (0–7).
    pub owner_perm: u16,
    /// Group permissions as rwx bits (0–7).
    pub group_perm: u16,
    /// Everyone permissions as rwx bits (0–7).
    pub everyone_perm: u16,
    /// Named user / group ACL entries (extended entries beyond the three base identities).
    pub entries: Vec<AclEntry>,
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
            data: RecordData::new(record_header, Default::default(), None),
            header: record_header,
            trailer: Default::default(),
        };
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("mock_file.txt");

        // Create a mock file to set attributes on
        File::create(&file_path).unwrap();

        // Set the attributes
        let result = set_file_attributes(&file_path, &record, attribute::ATTRIBUTE_TIMESTAMPS);
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
            attribute::ATTRIBUTE_TIMESTAMPS | attribute::ATTRIBUTE_PERMISSIONS,
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
        let result = archive.extract_file_by_name_with_attr(
            "backup/file.txt",
            &dest_path,
            attribute::ATTRIBUTE_NONE,
        );

        assert!(result.is_ok());
        assert!(dest_path.exists());
    }

    // -----------------------------------------------------------------------
    // ACL tests — use resources/test/test_acl.bff which has:
    //   record[0]: directory './'  with ACL (num_entries=5, acl_len=32)
    //              owner_perm=7, group_perm=7, everyone_perm=0
    //              ACE[0]: user 204, allow, rwx=7
    //              ACE[1]: group 21800, allow, rwx=7
    //   record[1]: file 'backup/file.txt' with no ACL
    // -----------------------------------------------------------------------

    #[test]
    fn test_acl_record_has_acl() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let records = archive.records();

        // Directory record has ACL; file record does not.
        assert!(records[0].acl().is_some(), "directory should have ACL");
        assert!(records[1].acl().is_none(), "plain file should have no ACL");
    }

    #[test]
    fn test_acl_descriptor_fields() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap();

        assert_eq!(acl.num_entries, 5);
        assert_eq!(acl.version, 2);
        assert_eq!(acl.acl_len, 32);
        assert_eq!(acl.acl_mode, crate::bff::S_IXACL);
    }

    #[test]
    fn test_acl_base_permissions() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap();

        assert_eq!(acl.owner_perm, 7, "owner should have rwx");
        assert_eq!(acl.group_perm, 7, "group should have rwx");
        assert_eq!(acl.everyone_perm, 0, "everyone should have no permissions");
    }

    #[test]
    fn test_acl_extended_entry_count() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap();

        // num_entries=5: 3 base identities + 2 extended = 2 AclEntry values
        assert_eq!(acl.entries.len(), 2);
    }

    #[test]
    fn test_acl_user_entry() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap();

        let user_entry = &acl.entries[0];
        assert_eq!(user_entry.principal_type, AclPrincipalType::User);
        assert_eq!(user_entry.principal_id, 204);
        assert!(user_entry.is_allow());
        assert_eq!(user_entry.rwx(), 7);
    }

    #[test]
    fn test_acl_group_entry() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap();

        let group_entry = &acl.entries[1];
        assert_eq!(group_entry.principal_type, AclPrincipalType::Group);
        assert_eq!(group_entry.principal_id, 21800);
        assert!(group_entry.is_allow());
        assert_eq!(group_entry.rwx(), 7);
    }

    #[test]
    fn test_acl_file_still_extractable() {
        // Verify that ACL presence doesn't corrupt file_position for the
        // subsequent file record — we should still be able to extract it.
        let file = open_bff_file("test_acl.bff").unwrap();
        let temp_dir = tempdir().unwrap();
        let dest_path = temp_dir.path().join("out.txt");

        let mut archive = Archive::new(file).unwrap();
        let result = archive.extract_file_by_name_with_attr(
            "backup/file.txt",
            &dest_path,
            attribute::ATTRIBUTE_NONE,
        );

        assert!(result.is_ok());
        assert!(dest_path.exists());
        let contents = std::fs::read_to_string(&dest_path).unwrap();
        assert_eq!(contents, "hello from bff\n");
    }

    #[test]
    fn test_parse_acl_payload_no_extended_entries() {
        // 3 base identities only (num_entries=3): just the 8-byte base header
        let payload: Vec<u8> = vec![
            0x00, 0x00, // reserved
            0x05, 0x00, // owner_perm = 5 (r-x)
            0x04, 0x00, // group_perm = 4 (r--)
            0x00, 0x00, // everyone_perm = 0
        ];
        let (owner, group, everyone, entries) = parse_acl_payload(&payload, 3);
        assert_eq!(owner, 5);
        assert_eq!(group, 4);
        assert_eq!(everyone, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_acl_payload_deny_ace() {
        // An ACE with access_word bit 15 clear = deny ACE
        let mut payload: Vec<u8> = vec![
            0x00, 0x00, // reserved
            0x07, 0x00, // owner_perm = 7
            0x07, 0x00, // group_perm = 7
            0x00, 0x00, // everyone_perm = 0
        ];
        // deny ACE: access_word = 0x0007 (bit 15 clear = deny, rwx=7)
        payload.extend_from_slice(&[
            0x0c, 0x00, // ace_len = 12
            0x07, 0x00, // access_word = 0x0007 (deny)
            0x08, 0x00, // id_block_len = 8
            0x01, 0x00, // principal_type = 1 (user)
            0x00, 0x00, 0x00, 0x64, // principal_id = 100 (big-endian)
        ]);
        let (_owner, _group, _everyone, entries) = parse_acl_payload(&payload, 4);
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].is_allow(), "ACE should be a deny entry");
        assert_eq!(entries[0].rwx(), 7);
        assert_eq!(entries[0].principal_id, 100);
    }
}

