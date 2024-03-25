use crate::Result;
use std::io::Read;

/// All BFF files should contain this magic number.
pub const FILE_MAGIC: u32 = 0xea6b0009; //0x09006BEA;
/// A compressed record should contain this magic number.
pub const HUFFMAN_MAGIC: u16 = 0xEA6C;
/// All records should contain one of these magic numbers.
pub const HEADER_MAGICS: [u16; 3] = [0xEA6B, HUFFMAN_MAGIC, 0xEA6D];

/// Representation of the file header.
///
/// Some data is not identified at the moment and named "unk*"
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FileHeader {
    /// Magic number
    pub magic: u32,
    pub checksum: u32,
    pub current_date: u32,
    pub starting_date: u32,
    pub unk10: u32,
    pub disk_name: [u8; 8],
    pub unk1_c: u32,
    pub unk20: u32,
    pub filesystem_name: [u8; 8],
    pub unk2_c: u32,
    pub unk30: u32,
    /// Typically contains the username of the build user.
    pub username: [u8; 8],
    pub unk3_c: u32,
    pub unk40: u32,
    pub unk44: u32,
}

/// Represntation of a record header.
///
/// Some data is not identified at the moment and named "unk*"
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordHeader {
    /// Directories seems to have 0x0D, files found having 0x0F, 0x10, 0x11, 0x12; lpp_name has 0x0A
    pub unk00: u8,
    /// typical record has 0x0B, some offset data found having 0x07
    pub unk01: u8,
    /// Magic number
    pub magic: u16,
    pub unk04: u32,
    /// Maybe directory ID or counter, always 0 for files
    pub unk08: u32,
    /// File mode (rwx...) as bit represntation
    pub mode: u32,
    /// User ID number of the file
    pub uid: u32,
    /// Group ID number of the file
    pub gid: u32,
    /// File size
    pub size: u32,
    pub atime: u32,
    /// Last modified timestamp of the file
    pub mtime: u32,
    pub time24: u32,
    /// Always last bits: 1010 (10)
    pub unk28: u32,
    /// Always last bits: 111 (7)
    pub unk2_c: u32,
    /// always 0
    pub unk30: u32,
    /// always 0
    pub unk34: u32,
    pub compressed_size: u32,
    /// always 0
    pub unk3_c: u32,
}

/// Representation of the data after each record header and record file name.
///
/// Some data is not identified at the moment and named "unk*"
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordTrailer {
    pub unk00: u32,
    pub unk04: u32,
    pub unk08: u32,
    pub unk0_c: u32,
    pub unk10: u32,
    pub unk14: u32,
    pub unk18: u32,
    pub unk1_c: u32,
    pub unk20: u32,
    pub unk24: u32,
}

/// Read string from stream until NULL.
pub fn read_aligned_string<R: ?Sized + Read>(reader: &mut R) -> Result<String> {
    let mut result: Vec<u8> = vec![];
    loop {
        let mut data = [0; 8];
        let len = reader.read(&mut data)?;
        if len == 0 {
            return Ok(String::from_utf8_lossy(&result).into());
        }
        for c in data {
            if c == 0 {
                return Ok(String::from_utf8_lossy(&result).into());
            }
            result.push(c);
        }
    }
}
