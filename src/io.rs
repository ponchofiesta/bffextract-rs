use std::{cmp::min, io::{Error, Read, Result as IoResult, Seek, SeekFrom}};

pub(crate) struct SelectiveReader<'a, R>
where
    R: Read + Seek,
{
    reader: &'a mut R,
    start: u64,
    size: u64,
}

impl<'a, R> SelectiveReader<'a, R> where R: Read + Seek {
    pub fn new(reader: &'a mut R, start: u64, size: u64) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(start))?;
        Ok(SelectiveReader {reader, start, size})
    }
}

impl<'a, R> Read for SelectiveReader<'a, R> where R: Read + Seek {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let pos = self.reader.seek(SeekFrom::Current(0))?;
        let max_buf_len = self.start as usize + self.size as usize - pos as usize;
        let buf_len = min(max_buf_len, buf.len());
        let mut buffer = vec![0u8; buf_len];
        self.reader.read(&mut buffer)?;
        for i in 0..buf_len {
            buf[i] = buffer[i];
        }
        Ok(buf_len)
    }
}

impl<'a, R> Seek for SelectiveReader<'a, R> where R: Read + Seek {
    fn seek(&mut self, pos: SeekFrom) -> IoResult<u64> {
        let get_pos = |pos: i64| {
            let pos = self.start as i64 + pos;
            if pos < self.start as i64 || pos > self.start as i64 + self.size as i64 {
                return Err(Error::other("Out of stream boundaries"));
            }
            Ok(pos)
        };
        let pos = match pos {
            SeekFrom::Start(pos) => SeekFrom::Start(get_pos(pos as i64)? as u64),
            SeekFrom::End(pos) => SeekFrom::End(get_pos(pos)?),
            SeekFrom::Current(pos) => SeekFrom::Current(get_pos(pos)?),
        };
        self.reader.seek(pos)
    }
}
