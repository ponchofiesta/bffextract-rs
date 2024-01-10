
use std::slice::from_raw_parts_mut;
use std::{
    cmp::min,
    io::{Read, Write},
};
use std::{io, mem};

/// Read defined size of reader stream and copy to writer stream.
pub fn copy_stream<R: Read, W: Write>(reader: &mut R, writer: &mut W, size: usize) -> Result<(), io::Error> {
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

pub fn read_struct<R: Read, T: Sized>(reader: &mut R) -> io::Result<T> {
    let mut obj: T = unsafe { mem::zeroed() };
    let size = mem::size_of::<T>();
    let buffer_slice = unsafe { from_raw_parts_mut(&mut obj as *mut _ as *mut u8, size) };
    reader.read_exact(buffer_slice)?;
    Ok(obj)
}
