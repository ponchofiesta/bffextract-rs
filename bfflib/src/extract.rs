use std::{
    fs::File,
    io::{self, copy, BufWriter, Read, Seek, SeekFrom, Take},
    path::{Path, PathBuf},
};

use file_mode::FileType;
#[cfg(unix)]
use file_mode::ModePath;
use filetime::{set_file_times, FileTime};
#[cfg(unix)]
use std::os::unix::fs::chown;
#[cfg(unix)]
use std::os::unix::fs::symlink;

use crate::{
    archive::Record,
    attribute,
    bff::HUFFMAN_MAGIC,
    huffman::HuffmanDecoder,
    util::{create_dir_all, create_parent_dir_all},
    Error, Result,
};

#[derive(Debug)]
pub struct ExtractedEntry {
    pub record: PathBuf,
    pub destination: PathBuf,
}

#[derive(Debug)]
pub struct SkippedEntry {
    pub record: PathBuf,
    pub destination: PathBuf,
    pub error: Error,
}

#[derive(Debug)]
pub struct ExtractionWarning {
    pub record: PathBuf,
    pub destination: PathBuf,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct ExtractionReport {
    pub extracted_entries: Vec<ExtractedEntry>,
    pub skipped_entries: Vec<SkippedEntry>,
    pub warnings: Vec<ExtractionWarning>,
}

pub(crate) enum ExtractionDisposition {
    Extracted,
    ExtractedWithWarning(String),
    Skipped(Error),
}

pub(crate) struct ArchiveSource<R> {
    reader: R,
}

impl<R> ArchiveSource<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self { reader }
    }
}

impl<R: Read + Seek> ArchiveSource<R> {
    pub(crate) fn open<'a>(&'a mut self, record: &Record) -> Result<Option<RecordReader<'a>>> {
        open_record_reader(&mut self.reader, record, false)
    }

    pub(crate) fn open_raw<'a>(&'a mut self, record: &Record) -> Result<Option<RecordReader<'a>>> {
        open_record_reader(&mut self.reader, record, true)
    }

    pub(crate) fn read_text(&mut self, record: &Record) -> Result<Option<String>> {
        if !record
            .mode()
            .file_type()
            .is_some_and(|file_type| file_type.is_regular_file())
        {
            return Ok(None);
        }

        self.reader
            .seek(SeekFrom::Start(record.file_position() as u64))?;
        let mut take = (&mut self.reader as &mut dyn Read).take(record.compressed_size() as u64);
        let mut buf = Vec::with_capacity(record.compressed_size() as usize);
        take.read_to_end(&mut buf)?;

        Ok(String::from_utf8(buf).ok())
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
            RecordReader::Raw(reader) => reader.read(buf),
            RecordReader::Huffman(reader) => reader.read(buf),
        }
    }
}

/// Extract a single file to destination folder.
pub(crate) fn extract_file<R: Read, D: AsRef<Path>>(reader: &mut R, destination: D) -> Result<()> {
    let writer = File::create(destination)?;
    let mut writer = BufWriter::new(writer);
    copy(reader, &mut writer).map(|_| ()).map_err(Into::into)
}

pub(crate) fn extract_record_with_attr<R: Read + Seek, D: AsRef<Path>>(
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
            let target = record
                .symlink()
                .ok_or_else(|| Error::MissingSymlinkTarget(record.filename().to_path_buf()))?;
            symlink(target, destination.as_ref())?;
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

pub(crate) fn extract_record_best_effort_with_attr<R: Read + Seek, D: AsRef<Path>>(
    source: &mut ArchiveSource<R>,
    record: &Record,
    destination: D,
    attributes: u8,
) -> ExtractionDisposition {
    match extract_record_with_attr(source, record, &destination, attributes) {
        Ok(()) => ExtractionDisposition::Extracted,
        Err(Error::UnsupportedFileType(_))
            if record
                .mode()
                .file_type()
                .is_some_and(is_unsupported_filetype) =>
        {
            let destination = destination.as_ref();
            let warning = format!(
                "Unsupported file type {:?}. Will create an empty file instead.",
                record.mode().file_type()
            );

            let fallback = (|| -> Result<()> {
                create_parent_dir_all(&destination)?;
                File::create(destination)?;
                set_file_attributes(destination, record, attributes)?;
                Ok(())
            })();

            match fallback {
                Ok(()) => ExtractionDisposition::ExtractedWithWarning(warning),
                Err(error) => ExtractionDisposition::Skipped(error),
            }
        }
        Err(error) => ExtractionDisposition::Skipped(error),
    }
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

fn open_record_reader<'a, R: Read + Seek>(
    reader: &'a mut R,
    record: &Record,
    raw: bool,
) -> Result<Option<RecordReader<'a>>> {
    match record.mode().file_type() {
        Some(file_type) if file_type.is_regular_file() => {
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

pub(crate) fn set_file_attributes<P: AsRef<Path>>(
    path: P,
    record: &Record,
    attributes: u8,
) -> io::Result<()> {
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
                .map_err(io::Error::other)?;
        }
    }

    Ok(())
}
