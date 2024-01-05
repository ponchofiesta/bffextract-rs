use anyhow::{anyhow, Result};
use normalize_path::NormalizePath;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::huffman;
use crate::util::copy_stream;

pub const FILE_MAGIC: u32 = 0xea6b0009; //0x09006BEA;
pub const HUFFMAN_MAGIC: u16 = 0xEA6C;
pub const HEADER_MAGICS: [u16; 3] = [0xEA6B, HUFFMAN_MAGIC, 0xEA6D];

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct FileHeader {
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
    pub username: [u8; 8],
    pub unk3_c: u32,
    pub unk40: u32,
    pub unk44: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct RecordHeader {
    pub unk00: u16,
    pub magic: u16,
    pub unk04: u32,
    pub unk08: u32,
    pub unk0_c: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub time1_c: u32,
    pub time20: u32,
    pub time24: u32,
    pub unk28: u32,
    pub unk2_c: u32,
    pub unk30: u32,
    pub unk34: u32,
    pub compressed_size: u32,
    pub unk3_c: u32,
}

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
pub fn read_aligned_string<R: Read>(reader: &mut R) -> Result<String> {
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

/// Read date from stream and write to file.
pub fn extract_record<R: Read, P: AsRef<Path>>(
    reader: &mut R,
    name: &str,
    size: usize,
    decompress: bool,
    target_dir: P,
) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Empty filename provided."));
    }
    let out_name = target_dir.as_ref().join(name).normalize();
    let dir = out_name
        .parent()
        .ok_or_else(|| anyhow!(format!("No parent dir for path {}", out_name.display())))?;
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    let mut writer = File::create(&out_name)?;
    if decompress {
        huffman::decompress_stream(reader, &mut writer, size)?;
        //copy_stream(reader, &mut writer, size)?;
    } else {
        copy_stream(reader, &mut writer, size)?;
    }
    Ok(())
}
