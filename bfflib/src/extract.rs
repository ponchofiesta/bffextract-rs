use std::{
    fs::File,
    io::{self, copy, BufWriter, Read, Seek, SeekFrom, Take},
    path::Path,
};

#[cfg(unix)]
use file_mode::ModePath;
use filetime::{set_file_times, FileTime};
#[cfg(unix)]
use std::os::unix::fs::chown;

use crate::{
    archive::Record, attribute, bff::HUFFMAN_MAGIC, huffman::HuffmanDecoder, Error, Result,
};

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
