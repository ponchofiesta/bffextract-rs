use sha2::{Sha256, Digest};

use crate::bff::{Record, RecordDiff, RecordDiffContent, RecordDiffField, HUFFMAN_MAGIC};
use crate::error::{BffError, BffReadError};
use crate::huffman::HuffmanReader;
use std::io::{BufWriter, Seek, SeekFrom};
use std::mem;
use std::slice::from_raw_parts_mut;
use std::str::from_utf8;
use std::{
    cmp::min,
    io::{Read, Result, Write},
};

pub(crate) trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Read defined `size` of `reader` stream and copy to `writer` stream.
pub fn copy_stream<R: Read, W: Write>(reader: &mut R, writer: &mut W, size: usize) -> Result<()> {
    const BUF_SIZE: usize = 1024;
    let mut total = 0;
    let mut to_read = min(BUF_SIZE, size);
    while total < size {
        let mut data = vec![0; to_read];
        reader.read(&mut data)?;
        writer.write_all(&data)?;
        total += to_read;
        to_read = min(BUF_SIZE, size - total);
    }
    Ok(())
}

/// Read binary data from a stream `reader` and map the bytes on the resulting
/// struct. Target struct needs to be packed.
pub(crate) fn read_struct<R: Read, T: Sized>(reader: &mut R) -> Result<T> {
    let mut obj: T = unsafe { mem::zeroed() };
    let size = mem::size_of::<T>();
    let buffer_slice = unsafe { from_raw_parts_mut(&mut obj as *mut _ as *mut u8, size) };
    reader.read_exact(buffer_slice)?;
    Ok(obj)
}

pub enum ContentType {
    Plaintext,
    Binary,
}

/// Try to determine if the data is plaintext or binary
pub fn get_content_type(reader: &mut dyn Read, size: usize) -> Result<ContentType> {
    let length = min(size, 2048);
    let mut buffer = vec![0; length];
    reader.read_exact(&mut buffer)?;
    Ok(match from_utf8(&buffer) {
        Ok(_) => ContentType::Plaintext,
        Err(_) => ContentType::Binary,
    })
}

pub fn compare_records<R1, R2>(
    left_reader: &mut R1,
    left_records: &[Record],
    right_reader: &mut R2,
    right_records: &[Record],
) -> std::result::Result<Vec<RecordDiff>, BffError>
where
    R1: Read + Seek,
    R2: Read + Seek,
{
    use RecordDiffField::*;

    let mut buf = &[0u8; 2048];

    let mut left_diffs: Vec<RecordDiff> = left_records
        .into_iter()
        .filter_map(|l| {
            let r = right_records.into_iter().find(|r| l.filename == r.filename);
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

                // Compare content
                let left_diff_content = get_diff_content(left_reader, l);
                let right_diff_content = get_diff_content(right_reader, r);
                match (left_diff_content, right_diff_content) {
                    (
                        RecordDiffContent::Plaintext(left_content),
                        RecordDiffContent::Plaintext(right_content),
                    ) => {
                        if left_content != right_content {
                            diffs.push(Content(
                                RecordDiffContent::Plaintext(left_content),
                                RecordDiffContent::Plaintext(right_content),
                            ));
                        }
                    }
                    (RecordDiffContent::Plaintext(left_content), RecordDiffContent::Binary) => {
                        diffs.push(Content(
                            RecordDiffContent::Plaintext(left_content),
                            RecordDiffContent::Binary,
                        ));
                    }
                    (RecordDiffContent::Binary, RecordDiffContent::Plaintext(right_content)) => {
                        diffs.push(Content(
                            RecordDiffContent::Binary,
                            RecordDiffContent::Plaintext(right_content),
                        ));
                    }
                    (RecordDiffContent::Binary, RecordDiffContent::Binary) => {
                        if !record_bin_equal(left_reader, l, right_reader, r) {
                            diffs.push(Content(
                                RecordDiffContent::Binary,
                                RecordDiffContent::Binary,
                            ))
                        }
                    }
                };
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

    let right_diffs: Vec<RecordDiff> = right_records
        .into_iter()
        .filter_map(|r| {
            let l = left_records.into_iter().find(|l| l.filename == r.filename);
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
    Ok(left_diffs)
}

fn record_bin_equal<R1, R2>(
    left_reader: &mut R1,
    l: &Record,
    right_reader: &mut R2,
    r: &Record,
) -> bool
where
    R1: Read + Seek,
    R2: Read + Seek,
{
    let mut hasher = Sha256::new();
    let result = hasher.finalize();
}

fn get_checksum<R>(reader: &mut R, record: &Record) -> 

fn get_diff_content<R>(reader: &mut R, record: &Record) -> RecordDiffContent
where
    R: Read + Seek,
{
    let content_type;
    reader
        .seek(SeekFrom::Start(record.file_position as u64))
        .unwrap();
    if record.magic == HUFFMAN_MAGIC {
        let mut left_reader = HuffmanReader::from(reader, record.compressed_size as usize).unwrap();
        content_type = get_content_type(&mut left_reader, record.size as usize).unwrap();
    } else {
        content_type = get_content_type(reader, record.size as usize).unwrap();
    }
    reader
        .seek(SeekFrom::Start(record.file_position as u64))
        .unwrap();
    let diff_content = match content_type {
        ContentType::Plaintext => {
            let mut buf = BufWriter::new(Vec::new());
            copy_stream(reader, &mut buf, record.size as usize).unwrap();
            let bytes = buf.into_inner().unwrap();
            let content = String::from_utf8(bytes).unwrap();
            RecordDiffContent::Plaintext(content)
        }
        ContentType::Binary => RecordDiffContent::Binary,
    };
    diff_content
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[derive(Debug, PartialEq)]
    #[repr(C, packed)]
    struct ReadStruct {
        pub a: u32,
        pub b: u16,
        pub c: u32,
    }

    #[test]
    fn copy_stream_has_correct_size() -> Result<()> {
        let mut stream = Cursor::new(b"abcdefghijklmnopqrstuvwxyz");
        let mut result: Vec<u8> = vec![];

        copy_stream(&mut stream, &mut result, 5)?;

        assert_eq!(result, b"abcde");
        Ok(())
    }

    #[test]
    fn read_struct_has_correct_fields() -> Result<()> {
        let mut stream = Cursor::new(b"\x01\x00\x00\x00\x02\x00\x03\x00\x00\x00\x10\x11");

        let result = read_struct::<Cursor<_>, ReadStruct>(&mut stream)?;

        let expected = ReadStruct { a: 1, b: 2, c: 3 };
        assert_eq!(result, expected);

        Ok(())
    }
}
