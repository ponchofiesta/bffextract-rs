//! Decoding of compressed BFF record data

use crate::error;
use std::io::{Read, Write};

/// Huffman decompression of a single record data
struct HuffmanDecompressor {
    /// Amount of bytes read while decompressing
    total_read: usize,
    /// Amount of Huffman tree levels
    treelevels: usize,
    inodesin: Vec<u8>,
    /// Symbols read
    symbolsin: Vec<u8>,
    /// Huffman tree
    tree: Vec<Vec<u8>>,
    symbol_size: usize,
    size: usize,
}

impl HuffmanDecompressor {
    fn new() -> Self {
        HuffmanDecompressor {
            total_read: 0,
            treelevels: 0,
            inodesin: Vec::new(),
            symbolsin: Vec::new(),
            tree: Vec::new(),
            symbol_size: 0,
            size: 0,
        }
    }

    /// Decompress data of a record.
    ///
    /// Reads a maximum amount of bytes defined by `size` from `reader` and extracts to `writer`.
    fn decompress_stream<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        size: usize,
    ) -> Result<(), error::BffError> {
        self.size = size;
        self.parse_header(reader)?;
        self.decode(reader, writer)?;
        Ok(())
    }

    /// Read and parse the data header. Creates the symbol table and the Huffman tree.
    fn parse_header<R: Read>(&mut self, reader: &mut R) -> Result<(), error::BffError> {
        let mut buffer = vec![0; 1];
        reader
            .read_exact(&mut buffer)
            .map_err(|err| error::BffReadError::IoError(err))?;
        self.treelevels = buffer[0] as usize;
        self.total_read = 1;
        self.inodesin = vec![0; self.treelevels];
        self.symbolsin = vec![0; self.treelevels];
        self.tree = vec![Vec::new(); self.treelevels];
        self.treelevels -= 1;
        self.symbol_size = 1;

        for i in 0..=self.treelevels {
            //let byte = reader.bytes().next().unwrap_or(Ok(0)).unwrap();
            reader
                .read_exact(&mut buffer)
                .map_err(|err| error::BffReadError::IoError(err))?;
            self.symbolsin[i] = buffer[0];
            self.symbol_size += self.symbolsin[i] as usize;
        }

        self.total_read += self.treelevels as usize;

        if self.symbol_size > 256 {
            return Err(error::BffReadError::BadSymbolTable.into());
        }

        self.symbolsin[self.treelevels as usize] += 1;

        for i in 0..=self.treelevels {
            let mut symbol = Vec::new();
            for _ in 0..self.symbolsin[i as usize] {
                reader
                    .read_exact(&mut buffer)
                    .map_err(|err| error::BffReadError::IoError(err))?;
                symbol.push(buffer[0]);
            }
            self.tree[i as usize] = symbol;
            self.total_read += self.symbolsin[i] as usize;
        }

        self.symbolsin[self.treelevels] += 1;

        self.fill_inodesin(0);
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

    /// Decode the compressed data after the tree and symbol table was created.
    fn decode<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), error::BffError> {
        let mut level = 0;
        let mut code = 0;
        let mut buffer = [0; 1];
        let mut symbol;
        let mut inlevelindex;
        let treelens: Vec<usize> = self.tree.iter().map(|l| l.len()).collect();

        while self.total_read < self.size {
            reader
                .read_exact(&mut buffer)
                .map_err(|err| error::BffReadError::IoError(err))?;
            self.total_read += 1;
            for i in (0..=7).rev() {
                code = (code << 1) | ((buffer[0] >> i) & 1);
                if code >= self.inodesin[level] {
                    inlevelindex = (code - self.inodesin[level]) as usize;
                    if inlevelindex > self.symbolsin[level] as usize {
                        return Err(error::BffReadError::InvalidLevelIndex.into());
                    }
                    if treelens[level] <= inlevelindex {
                        // Hopefully the end of the file
                        return Ok(());
                    }
                    symbol = self.tree[level][inlevelindex];
                    writer.write_all(&[symbol]).unwrap();
                    code = 0;
                    level = 0;
                } else {
                    level += 1;
                    if level > self.treelevels {
                        return Err(error::BffReadError::InvalidTreelevel.into());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Decompress a single record data
///
/// Reads a maximum amount of bytes defined by `size` from `reader` and extracts to `writer`.
pub fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    size: usize,
) -> Result<(), error::BffError> {
    let mut decompressor = HuffmanDecompressor::new();
    decompressor.decompress_stream(reader, writer, size)?;
    Ok(())
}
