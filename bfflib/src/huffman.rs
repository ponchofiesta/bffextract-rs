//! Decoding of compressed BFF record data

use crate::{Error, Result};
use std::{
    cmp::min,
    collections::VecDeque,
    io::{ErrorKind, Read},
};

/// A decoder for BFF file contents which is Huffman encoded.
pub struct HuffmanDecoder<R> {
    /// Source reader containing compressed data
    reader: R,
    code: u8,
    level: usize,
    /// Amount of Huffman tree levels
    treelevels: usize,
    inodesin: Vec<u8>,
    /// Symbols read
    symbolsin: Vec<u8>,
    /// Huffman tree
    tree: Vec<Vec<u8>>,
    treelens: Vec<usize>,
    symbol_size: usize,
    offset_buf: VecDeque<u8>,
}

impl<R: Read> HuffmanDecoder<R> {
    /// Create a new instance of `HuffmanDecoder` by providing a reader.
    ///
    /// It will read the bFF file header. If this fails or the header is invalid, an error will be returned.
    pub fn new(reader: R) -> Result<Self> {
        let mut decoder = HuffmanDecoder {
            reader,
            code: 0,
            level: 0,
            treelevels: 0,
            inodesin: vec![],
            symbolsin: vec![],
            tree: vec![],
            treelens: vec![],
            symbol_size: 0,
            offset_buf: VecDeque::with_capacity(8),
        };
        decoder.parse_header()?;
        Ok(decoder)
    }

    /// Read and parse the data header. Creates the symbol table and the Huffman tree.
    fn parse_header(&mut self) -> Result<()> {
        let mut buffer = vec![0; 1];
        self.reader.read_exact(&mut buffer)?;
        self.treelevels = buffer[0] as usize;
        self.inodesin = vec![0; self.treelevels];
        self.symbolsin = vec![0; self.treelevels];
        self.tree = vec![Vec::new(); self.treelevels];
        self.treelevels -= 1;
        self.symbol_size = 1;

        for i in 0..=self.treelevels {
            self.reader.read_exact(&mut buffer)?;
            self.symbolsin[i] = buffer[0];
            self.symbol_size += self.symbolsin[i] as usize;
        }

        if self.symbol_size > 256 {
            return Err(Error::BadSymbolTable);
        }

        self.symbolsin[self.treelevels as usize] += 1;

        for i in 0..=self.treelevels {
            let mut symbol = Vec::new();
            for _ in 0..self.symbolsin[i as usize] {
                self.reader.read_exact(&mut buffer)?;
                symbol.push(buffer[0]);
            }
            self.tree[i as usize] = symbol;
        }

        self.symbolsin[self.treelevels] += 1;

        self.fill_inodesin(0);
        self.treelens = self.tree.iter().map(|l| l.len()).collect();
        Ok(())
    }

    fn fill_inodesin(&mut self, level: usize) {
        if level < self.treelevels {
            self.fill_inodesin(level + 1);
            self.inodesin[level] = (self.inodesin[level + 1] + self.symbolsin[level + 1]) / 2;
        } else {
            self.inodesin[level] = 0;
        }
    }
}

impl<R: Read> Read for HuffmanDecoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buf_size = buf.len();
        let mut current_out = self.offset_buf.len();
        let mut buffer = [0; 1];
        let mut symbol;
        let mut inlevelindex;

        // Read in extracted bytes from previous call
        let offset_read_len = min(buf_size, self.offset_buf.len());
        for i in 0..offset_read_len {
            buf[i] = match self.offset_buf.pop_front() {
                Some(value) => value,
                None => break,
            }
        }
        if offset_read_len == buf_size {
            return Ok(offset_read_len);
        }

        // Read new bytes from input
        while current_out < buf_size {
            match self.reader.read_exact(&mut buffer) {
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(current_out),
                _ => (),
            };

            for i in (0..=7).rev() {
                self.code = (self.code << 1) | ((buffer[0] >> i) & 1);
                if self.code >= self.inodesin[self.level] {
                    inlevelindex = (self.code - self.inodesin[self.level]) as usize;
                    if inlevelindex > self.symbolsin[self.level] as usize {
                        return Err(std::io::Error::other(Error::InvalidLevelIndex));
                    }
                    if self.treelens[self.level] <= inlevelindex {
                        // Hopefully the end of the file
                        return Ok(current_out);
                    }
                    symbol = self.tree[self.level][inlevelindex];
                    if current_out >= buf_size {
                        self.offset_buf.push_back(symbol);
                    } else {
                        buf[current_out] = symbol;
                    }
                    current_out += 1;
                    self.code = 0;
                    self.level = 0;
                } else {
                    self.level += 1;
                    if self.level > self.treelevels {
                        return Err(std::io::Error::other(Error::InvalidTreelevel));
                    }
                }
            }
        }
        Ok(min(current_out, buf_size))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::{Read, Result}, path::{Path, PathBuf}};

    use super::HuffmanDecoder;

    fn get_resources_path() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("../resources/test");
        dir
    }

    fn open_decoder<P: AsRef<Path>>(filename: P) -> Result<impl Read> {
        let file = File::open(get_resources_path().join(filename))?;
        let decoder = HuffmanDecoder::new(file).map_err(|e| std::io::Error::other(e))?;
        Ok(decoder)
    }

    #[test]
    fn decode_file() -> Result<()> {
        let mut decoder = open_decoder("huffman_encoded.bin")?;
        let mut decoded_file = File::open(get_resources_path().join("huffman_decoded.bin"))?;
        let mut result = vec![];
        decoder.read_to_end(&mut result)?;
        let mut expected = vec![];
        decoded_file.read_to_end(&mut expected)?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn decode_read() -> Result<()> {
        let mut decoded_file = File::open(get_resources_path().join("huffman_decoded.bin"))?;
        let mut decoder = open_decoder("huffman_encoded.bin")?;
        let mut result = [0u8; 16];
        decoder.read(&mut result)?;
        let mut expected = [0u8; 16];
        decoded_file.read(&mut expected)?;
        assert_eq!(result, expected);
        Ok(())
    }
}
