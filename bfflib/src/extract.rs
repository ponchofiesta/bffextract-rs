use std::{
    fs::File,
    io::{self, copy, BufWriter, Read, Seek, SeekFrom, Take},
    path::Path,
};

use filetime::{set_file_times, FileTime};
#[cfg(unix)]
use file_mode::ModePath;
#[cfg(unix)]
use std::os::unix::fs::chown;

use crate::{
    archive::Record,
    attribute,
    bff::HUFFMAN_MAGIC,
    huffman::HuffmanDecoder,
    Error, Result,
};

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

/// Create a reader for contents of a record.
pub(crate) fn make_record_reader<'a, R: Read + Seek>(
    reader: &'a mut R,
    record: &Record,
) -> Result<Option<RecordReader<'a>>> {
    make_record_reader_raw(reader, record, false)
}

/// Create a reader for contents of a record.
///
/// Set `raw = true` to read the bytes as is without decoding huffman encoded data.
pub(crate) fn make_record_reader_raw<'a, R: Read + Seek>(
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