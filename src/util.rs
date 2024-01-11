use std::mem;
use std::slice::from_raw_parts_mut;
use std::{
    cmp::min,
    io::{Read, Result, Write},
};

#[cfg(not(windows))]
use users::{Groups, Users, UsersCache};

/// Read defined size of reader stream and copy to writer stream.
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

pub fn read_struct<R: Read, T: Sized>(reader: &mut R) -> Result<T> {
    let mut obj: T = unsafe { mem::zeroed() };
    let size = mem::size_of::<T>();
    let buffer_slice = unsafe { from_raw_parts_mut(&mut obj as *mut _ as *mut u8, size) };
    reader.read_exact(buffer_slice)?;
    Ok(obj)
}

#[cfg(windows)]
pub struct UserData;

#[cfg(not(windows))]
pub struct UserData {
    cache: UsersCache,
}

#[cfg(windows)]
impl UserData {
    pub fn new() -> Self {
        Self
    }

    pub fn get_username_by_uid(&self, _uid: u32) -> Option<String> {
        None
    }

    #[cfg(windows)]
    pub fn get_groupname_by_gid(&self, _gid: u32) -> Option<String> {
        None
    }
}

#[cfg(not(windows))]
impl UserData {
    pub fn new() -> Self {
        Self {
            cache: UsersCache::new(),
        }
    }

    pub fn get_username_by_uid(&self, uid: u32) -> Option<String> {
        self.cache
            .get_user_by_uid(uid)
            .and_then(|user| user.name().to_os_string().into_string().ok())
    }

    pub fn get_groupname_by_gid(&self, gid: u32) -> Option<String> {
        self.cache
            .get_group_by_gid(gid)
            .and_then(|group| group.name().to_os_string().into_string().ok())
    }
}
