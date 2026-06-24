//! Reading an BFF archive

use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use chrono::{DateTime, NaiveDateTime, Utc};
use file_mode::{FileType, Mode};
use normalize_path::NormalizePath;
#[cfg(unix)]
use std::os::unix::fs::symlink;

use crate::{
    acl::{
        build_acl_data, format_acl_text, RecordAcl, AIXC_ACL_MODE_FLAG, S_IXACL,
        TRAILER_INLINE_ACL_BYTES,
    },
    attribute,
    bff::{read_aligned_string, FileHeader, RecordHeader, FILE_MAGIC, HEADER_MAGICS},
    extract::{extract_file, set_file_attributes, ArchiveSource},
    util::{self, create_dir_all, create_parent_dir_all},
};
use crate::{Error, Result};

pub use crate::acl::{
    AclData, AclEntry, AclMetadata, AclPrincipalType, AixcAcl, AixcPermissions, Nfs4Acl,
    Nfs4AclEntry, Nfs4AclPrincipal,
};
pub use crate::extract::RecordReader;

/// Read BFF [FileHeader] from the reader
fn read_file_header<R: Read>(reader: &mut R) -> Result<FileHeader> {
    let file_header: FileHeader = util::read_struct(reader)?;
    if file_header.magic != FILE_MAGIC {
        let magic = file_header.magic;
        return Err(Error::InvalidFileMagic(magic));
    }
    Ok(file_header)
}

fn align_reader_to_eight<R: Seek>(reader: &mut R) -> Result<()> {
    let position = reader.stream_position()?;
    let aligned = (position + 7) & !7;
    if aligned > position {
        reader.seek(SeekFrom::Start(aligned))?;
    }
    Ok(())
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

    let record_trailer: RecordAcl = util::read_struct(reader)?;

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

    if record_header.mode & S_IXACL > 0 && record_trailer.acl_len > 0 {
        let acl_len = record_trailer.acl_len as usize;
        let padded_acl_len = (acl_len + 15) & !15;
        let acl_padding = padded_acl_len.saturating_sub(acl_len);
        if acl_padding > 0 {
            reader.seek(SeekFrom::Current(acl_padding as i64))?;
        }
    }

    // Variable-length ACL payloads are padded to the next 8-byte boundary
    // before the file data or next record begins.
    align_reader_to_eight(reader)?;

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

fn record_index_by_filename<P: AsRef<Path>>(records: &[Record], filename: P) -> Option<usize> {
    records
        .iter()
        .position(|record| record.filename() == filename.as_ref())
}

/// A BFF archive
pub struct Archive<R> {
    source: ArchiveSource<R>,
    header: FileHeader,
    records_start_pos: u64,
    records: Vec<Record>,
}

impl<R: Read + Seek> Archive<R> {
    /// Creates a new Archive instance and reads the file informations and info about all records.
    pub fn new(mut reader: R) -> Result<Self> {
        let header = read_file_header(&mut reader)?;
        let records_start_pos = reader.stream_position()?;
        let mut records = read_records(&mut reader)?;
        attach_nfs4_acl_texts(&mut reader, &mut records)?;
        let archive = Self {
            source: ArchiveSource::new(reader),
            header,
            records_start_pos,
            records,
        };
        Ok(archive)
    }

    /// Returns the archive records
    pub fn records(&self) -> &[Record] {
        &self.records
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

    fn record_index_by_filename<P: AsRef<Path>>(&self, filename: P) -> Option<usize> {
        record_index_by_filename(&self.records, filename)
    }

    /// Creates a reader for a specific file.
    pub fn file<'a, P: AsRef<Path>>(&'a mut self, filename: P) -> Result<Option<RecordReader<'a>>> {
        let index = self
            .record_index_by_filename(&filename)
            .ok_or(Error::FileNotFound)?;
        let (source, records) = (&mut self.source, &self.records);
        source.open(&records[index])
    }

    /// Creates a raw reader for a specific file without decoding.
    pub fn raw_file<'a, P: AsRef<Path>>(
        &'a mut self,
        filename: P,
    ) -> Result<Option<RecordReader<'a>>> {
        let index = self
            .record_index_by_filename(&filename)
            .ok_or(Error::FileNotFound)?;
        let (source, records) = (&mut self.source, &self.records);
        source.open_raw(&records[index])
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
        let index = self
            .record_index_by_filename(&filename)
            .ok_or(Error::FileNotFound)?;
        let (source, records) = (&mut self.source, &self.records);
        extract_record_with_attr(source, &records[index], destination, attributes)
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
        extract_record_with_attr(&mut self.source, record, destination, attributes)
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
        let source = &mut self.source;
        for record in self.records.iter() {
            if when(&record) {
                let target_path = destination.as_ref().join(record.filename()).normalize();
                match extract_record_with_attr(source, record, &target_path, attributes) {
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

fn extract_record_with_attr<R: Read + Seek, D: AsRef<Path>>(
    source: &mut ArchiveSource<R>,
    record: &Record,
    destination: D,
    attributes: u8,
) -> Result<()> {
    match record.mode().file_type() {
        Some(file_type) if file_type.is_directory() => Ok(create_dir_all(&destination)?),
        Some(file_type) if file_type.is_regular_file() => {
            create_parent_dir_all(&destination)?;
            let mut reader = source.open(record)?.ok_or(Error::FileNotFound)?;
            extract_file(&mut reader, &destination)
        }
        #[cfg(unix)]
        Some(file_type) if file_type.is_symbolic_link() => {
            create_parent_dir_all(&destination)?;
            symlink(&destination, record.symlink().unwrap())?;
            Ok(())
        }
        Some(file_type) if is_unsupported_filetype(file_type) => {
            create_parent_dir_all(&destination)?;
            eprintln!(
                "{}: Unsupported file type {:?}. Will create an empty file instead.",
                record.filename().display(),
                record.mode().file_type()
            );
            File::create(&destination)?;
            Ok(())
        }
        _ => Err(Error::UnsupportedFileType(format!(
            "{:?}",
            record.mode().file_type()
        ))),
    }?;

    set_file_attributes(&destination, record, attributes)?;

    Ok(())
}

fn is_unsupported_filetype(filetype: FileType) -> bool {
    let unsup = filetype.is_block_device()
        || filetype.is_character_device()
        || filetype.is_fifo()
        || filetype.is_socket();

    #[cfg(windows)]
    let unsup = unsup || filetype.is_symbolic_link();

    unsup
}

/// Container for all record data
#[derive(Clone, Debug)]
pub struct Record {
    data: RecordData,
    header: RecordHeader,
    trailer: RecordAcl,
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

    pub fn format_acl<F, G>(&self, resolve_uid: F, resolve_gid: G) -> Option<String>
    where
        F: Fn(u32) -> String,
        G: Fn(u32) -> String,
    {
        let acl = self.acl()?;
        Some(format_acl_text(
            self.filename(),
            self.uid(),
            self.gid(),
            acl,
            resolve_uid,
            resolve_gid,
        ))
    }

    pub fn header(&self) -> &RecordHeader {
        &self.header
    }
    pub fn trailer(&self) -> &RecordAcl {
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
    pub fn new(header: RecordHeader, trailer: RecordAcl, acl_payload: Option<Vec<u8>>) -> Self {
        let acl = build_acl_data(header.mode, &trailer, acl_payload);
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

pub fn format_acl_aix_text<F, G>(record: &Record, resolve_uid: F, resolve_gid: G) -> Option<String>
where
    F: Fn(u32) -> String,
    G: Fn(u32) -> String,
{
    record.format_acl(resolve_uid, resolve_gid)
}

fn attach_nfs4_acl_texts<R: Read + Seek>(reader: &mut R, records: &mut [Record]) -> Result<()> {
    let mut source = ArchiveSource::new(reader);
    let mut pending_nfs4 = Vec::new();

    for index in 0..records.len() {
        if records[index]
            .acl()
            .is_some_and(|acl| acl.acl_mode() & AIXC_ACL_MODE_FLAG == 0)
        {
            pending_nfs4.push(index);
        }

        let is_synthetic_acl_record = records[index]
            .mode()
            .file_type()
            .is_some_and(|file_type| file_type.is_regular_file())
            && records[index].filename().to_string_lossy().ends_with('/');

        if !is_synthetic_acl_record {
            continue;
        }

        let Some(text) = source.read_text(&records[index])? else {
            continue;
        };

        if !text.starts_with("*\n* ACL_type   NFS4") {
            continue;
        }

        if let Some(target_index) = pending_nfs4.pop() {
            if let Some(acl) = records[target_index].data.acl.as_mut() {
                acl.attach_nfs4_text(text);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bff;
    use crate::extract::ArchiveSource;

    use super::*;
    use filetime::FileTime;
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

        let mut source = ArchiveSource::new(&mut file);
        let mut reader = source.open(&records[1]).unwrap().unwrap();

        let result = extract_file(&mut reader, &dest_path);

        assert!(result.is_ok());
        assert!(dest_path.exists());
    }

    #[test]
    fn test_make_record_reader_unsupported_filetype() {
        let mut file = open_bff_file("test.bff").unwrap();
        file.seek(SeekFrom::Start(72)).unwrap();

        let records = read_records(&mut file).unwrap();

        let mut source = ArchiveSource::new(&mut file);
        let result = source.open(&records[0]);

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

        assert_eq!(acl.num_entries(), 5);
        assert_eq!(acl.version(), 2);
        assert_eq!(acl.acl_len(), 32);
        assert_eq!(acl.acl_mode(), crate::acl::S_IXACL);
    }

    #[test]
    fn test_acl_base_permissions() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap().as_aixc().unwrap();

        assert_eq!(acl.base.owner_perm, 7, "owner should have rwx");
        assert_eq!(acl.base.group_perm, 7, "group should have rwx");
        assert_eq!(
            acl.base.everyone_perm, 0,
            "everyone should have no permissions"
        );
    }

    #[test]
    fn test_acl_extended_entry_count() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap().as_aixc().unwrap();

        // num_entries=5: 3 base identities + 2 extended = 2 AclEntry values
        assert_eq!(acl.entries.len(), 2);
    }

    #[test]
    fn test_acl_user_entry() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap().as_aixc().unwrap();

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
        let acl = archive.records()[0].acl().unwrap().as_aixc().unwrap();

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
    fn test_acl_aixc_nfs4_reads_all_records() {
        let file = open_bff_file("acl_aixc_nfs4.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let records = archive.records();

        let names: Vec<_> = records
            .iter()
            .map(|record| record.filename().to_string_lossy().into_owned())
            .collect();

        assert_eq!(names.len(), 6);
        assert_eq!(
            names,
            vec![
                "acl",
                "acl/aixc",
                "acl/aixc.txt",
                "acl/nfs4",
                "acl/nfs4.txt",
                "acl/",
            ]
        );
    }

    #[test]
    fn test_acl_aixc_nfs4_detects_acl_kinds() {
        let file = open_bff_file("acl_aixc_nfs4.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let records = archive.records();

        assert_eq!(records[1].acl().unwrap().as_aixc().is_some(), true);
        assert_eq!(records[3].acl().unwrap().as_nfs4().is_some(), true);
    }

    #[test]
    fn test_acl_aixc_nfs4_preserves_nfs4_text_payload() {
        let file = open_bff_file("acl_aixc_nfs4.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[3].acl().unwrap();

        assert!(acl
            .as_nfs4()
            .and_then(|nfs4| nfs4.text.as_deref())
            .is_some_and(|text| text.starts_with("*\n* ACL_type   NFS4")));
    }

    #[test]
    fn test_acl_kind_prefers_parsed_compact_acl_shape() {
        let file = open_bff_file("test_acl.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let acl = archive.records()[0].acl().unwrap();

        assert_eq!(acl.as_aixc().is_some(), true);
    }

    #[test]
    fn test_format_acl_aix_text_formats_aixc() {
        let file = open_bff_file("acl_aixc_nfs4.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let records = archive.records();
        let record = records
            .iter()
            .find(|record| record.filename() == Path::new("acl/aixc"))
            .unwrap();

        let output = record
            .format_acl(|uid| uid.to_string(), |gid| gid.to_string())
            .unwrap();

        assert!(output.contains("* ACL_type   AIXC"));
        assert!(output.contains("permit   rw-     g:214"));
    }

    #[test]
    fn test_format_acl_aix_text_formats_nfs4() {
        let file = open_bff_file("acl_aixc_nfs4.bff").unwrap();
        let archive = Archive::new(file).unwrap();
        let records = archive.records();
        let record = records
            .iter()
            .find(|record| record.filename() == Path::new("acl/nfs4"))
            .unwrap();

        let output = record
            .format_acl(|uid| uid.to_string(), |gid| gid.to_string())
            .unwrap();

        assert!(output.contains("* ACL_type   NFS4"));
        assert!(output.contains("s:(OWNER@):     a       rwpRWxDaAdcCs   fidi"));
    }
}
