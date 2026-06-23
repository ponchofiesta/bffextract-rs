use crate::Result;
use std::io::Read;

/// All BFF files should contain this magic number.
pub const FILE_MAGIC: u32 = 0xea6b0009; //0x09006BEA;
/// A compressed record should contain this magic number.
pub const HUFFMAN_MAGIC: u16 = 0xEA6C;
/// All records should contain one of these magic numbers.
pub const HEADER_MAGICS: [u16; 3] = [0xEA6B, HUFFMAN_MAGIC, 0xEA6D];
/// File mode bit for ACLs.
pub const S_IXACL: u32 = 0x02000000;

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

impl Default for RecordHeader {
    fn default() -> Self {
        Self {
            unk00: 0,
            unk01: 0,
            magic: 0,
            unk04: 0,
            unk08: 0,
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            time24: 0,
            unk28: 0,
            unk2_c: 0,
            unk30: 0,
            unk34: 0,
            compressed_size: 0,
            unk3_c: 0,
        }
    }
}

/// The byte capacity for ACL payload bytes that are embedded directly inside
/// the [`RecordTrailer`] struct (fields `acl_payload_bytes`).
pub const TRAILER_INLINE_ACL_BYTES: usize = 24;

/// Representation of the data after each record header and record file name.
///
/// Layout (all fields little-endian, struct is 40 bytes on disk):
/// - `num_entries` / `version` / `acl_len` / `acl_mode`: the ACL descriptor (16 bytes).
/// - `acl_payload_bytes`: the first [`TRAILER_INLINE_ACL_BYTES`] bytes of the ACL payload
///   are stored inline here. When `acl_len > TRAILER_INLINE_ACL_BYTES`, the remaining
///   bytes follow the trailer in the file stream.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordTrailer {
    pub num_entries: u32,
    pub version: u32,
    pub acl_len: u32,
    pub acl_mode: u32,
    /// First 24 bytes of the ACL payload, stored inline inside the trailer region.
    pub acl_payload_bytes: [u8; TRAILER_INLINE_ACL_BYTES],
}

impl Default for RecordTrailer {
    fn default() -> Self {
        Self {
            num_entries: 0,
            version: 0,
            acl_len: 0,
            acl_mode: 0,
            acl_payload_bytes: [0u8; TRAILER_INLINE_ACL_BYTES],
        }
    }
}

/// Read string from stream until NULL.
pub(crate) fn read_aligned_string<R: ?Sized + Read>(reader: &mut R) -> Result<String> {
    let mut result: Vec<u8> = vec![];
    loop {
        let mut data = [0; 8];
        let len = reader.read(&mut data)?;
        if len == 0 {
            let s = String::from_utf8_lossy(&result);
            return Ok(first_segment(&s));
        }
        for c in data {
            if c == 0 {
                let s = String::from_utf8_lossy(&result);
                return Ok(first_segment(&s));
            }
            result.push(c);
        }
    }
}

/// Get the first segment of a string until a newline, tab, or vertical tab.
fn first_segment(text: &str) -> String {
    if let Some(index) = text.find(|c| matches!(c, '\n' | '\t' | '\x0B')) {
        text[..index].to_string()
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn read_aligned_string_default() {
        let mut reader = Cursor::new([97, 98, 99, 0, 1, 2, 3, 4]);
        let result = read_aligned_string(&mut reader).expect("Could not read aligned string.");
        assert_eq!(result, "abc");
    }

    #[test]
    fn read_aligned_string_double() {
        let mut reader = Cursor::new([97, 98, 99, 0, 1, 2, 3, 4, 97, 98, 99, 0, 1, 2, 3, 4]);
        let result = read_aligned_string(&mut reader).expect("Could not read aligned string.");
        assert_eq!(result, "abc");
    }

    #[test]
    fn read_aligned_string_long() {
        let mut reader = Cursor::new([
            97, 98, 99, 100, 101, 102, 103, 104, 97, 98, 99, 0, 1, 2, 3, 4,
        ]);
        let result = read_aligned_string(&mut reader).expect("Could not read aligned string.");
        assert_eq!(result, "abcdefghabc");
    }

    #[test]
    fn read_aligned_string_no_null() {
        let mut reader = Cursor::new([97, 98, 99, 1, 1, 2, 3, 4]);
        let result = read_aligned_string(&mut reader).expect("Could not read aligned string.");
        assert_eq!(result, "abc\u{1}\u{1}\u{2}\u{3}\u{4}");
    }

    #[test]
    fn read_aligned_string_no_8byte() {
        let mut reader = Cursor::new([97, 98, 99, 1, 1, 2, 3]);
        let result = read_aligned_string(&mut reader).expect("Could not read aligned string.");
        assert_eq!(result, "abc\u{1}\u{1}\u{2}\u{3}");
    }
}
