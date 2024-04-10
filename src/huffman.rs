//! Decoding of compressed BFF record data

use crate::error;
use std::io::Read;

/// Huffman decompression of a single record data
pub struct HuffmanReader<'a, R: Read> {
    /// Source reader containing compressed data
    reader: &'a mut R,
    /// Amount of bytes read while decompressing
    total_read: usize,
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
    /// Maximum amount of bytes in input stream
    size: usize,
    offset_buf: Vec<u8>,
}

impl<'a, R> HuffmanReader<'a, R>
where
    R: Read,
{
    pub fn from(reader: &'a mut R, size: usize) -> Result<Self, error::BffReadError> {
        let mut r = HuffmanReader {
            reader,
            total_read: 0,
            code: 0,
            level: 0,
            treelevels: 0,
            inodesin: vec![],
            symbolsin: vec![],
            tree: vec![],
            treelens: vec![],
            symbol_size: 0,
            size,
            offset_buf: Vec::with_capacity(8),
        };
        r.parse_header()?;
        Ok(r)
    }

    /// Read and parse the data header. Creates the symbol table and the Huffman tree.
    fn parse_header(&mut self) -> Result<(), error::BffReadError> {
        let mut buffer = vec![0; 1];
        self.reader
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
            self.reader
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
                self.reader
                    .read_exact(&mut buffer)
                    .map_err(|err| error::BffReadError::IoError(err))?;
                symbol.push(buffer[0]);
            }
            self.tree[i as usize] = symbol;
            self.total_read += self.symbolsin[i] as usize;
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

impl<'a, R> Read for HuffmanReader<'a, R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let buf_size = buf.len();
        let mut current_out = self.offset_buf.len();
        let mut buffer = [0; 1];
        let mut symbol;
        let mut inlevelindex;
        
        // Read in extracted bytes from previous call
        for i in 0..self.offset_buf.len() {
            buf[i] = self.offset_buf[i];
        }
        self.offset_buf = vec![];

        // Read new bytes from input
        while self.total_read < self.size && current_out < buf_size {
            
            self.reader
                .read_exact(&mut buffer)?;
            self.total_read += 1;
            
            for i in (0..=7).rev() {
                self.code = (self.code << 1) | ((buffer[0] >> i) & 1);
                if self.code >= self.inodesin[self.level] {
                    inlevelindex = (self.code - self.inodesin[self.level]) as usize;
                    if inlevelindex > self.symbolsin[self.level] as usize {
                        return Err(std::io::Error::other(error::BffReadError::InvalidLevelIndex));
                    }
                    if self.treelens[self.level] <= inlevelindex {
                        // Hopefully the end of the file
                        return Ok(current_out);
                    }
                    symbol = self.tree[self.level][inlevelindex];
                    if current_out >= buf_size {
                        self.offset_buf.push(symbol);
                    } else {
                        buf[current_out] = symbol;
                    }
                    current_out += 1;
                    self.code = 0;
                    self.level = 0;
                } else {
                    self.level += 1;
                    if self.level > self.treelevels {
                        return Err(std::io::Error::other(error::BffReadError::InvalidTreelevel));
                    }
                }
            }
        }
        Ok(current_out)
    }
}
