use std::io::{Seek, SeekFrom};
use std::mem;
use std::slice::from_raw_parts_mut;
use std::str::from_utf8;
use std::{
    cmp::min,
    io::{Read, Result, Write},
};

use crate::bff::{
    compare_records, Record, RecordDiff, RecordDiffField,
};
use crate::error::BffError;

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
pub fn get_content_type<R: Read + Seek>(
    reader: &mut R,
    position: u64,
    size: usize,
) -> Result<ContentType> {
    let length = min(size, 2048);
    let mut buffer = vec![0; length];
    reader.seek(SeekFrom::Start(position))?;
    reader.read_exact(&mut buffer)?;
    Ok(match from_utf8(&buffer) {
        Ok(_) => ContentType::Plaintext,
        Err(_) => ContentType::Binary,
    })
}

pub fn compare_files<R, R2>(
    reader: &mut R,
    records: &[Record],
    reader_diff: &mut R2,
    records_diff: &[Record],
) -> std::result::Result<Vec<RecordDiff>, BffError>
where
    R: Read + Seek,
    R2: Read + Seek,
{
    // Get metadata differences
    let mut record_diffs = compare_records(records, &records_diff);

    // Get content differences
    record_diffs
        .iter_mut()
        .filter(|record_diff| {
            // Get files that exist on both sides
            !record_diff
                .diffs
                .iter()
                .any(|field| matches!(field, RecordDiffField::Exists(_, _)))
        })
        .for_each(|record_diff| {
            // record_diff
            //     .diffs
            //     .push(RecordDiffField::Content(RecordDiffContent::Binary(0)));
        });

    Ok(record_diffs)
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
