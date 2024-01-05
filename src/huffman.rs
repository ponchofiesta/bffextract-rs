use anyhow::{anyhow, Result};
use std::io::{Read, Write};

pub struct HuffmanDecompressor {
    total_read: usize,
    treelevels: usize,
    inodesin: Vec<u8>,
    symbolsin: Vec<u8>,
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

    fn decompress_stream<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        size: usize,
    ) -> Result<()> {
        self.size = size;
        self.parse_header(reader)?;
        self.decode(reader, writer)?;
        Ok(())
    }

    fn parse_header<R: Read>(&mut self, reader: &mut R) -> Result<()> {
        let mut buffer = vec![0; 1];
        reader.read_exact(&mut buffer)?;
        self.treelevels = buffer[0] as usize;
        self.total_read = 1;
        self.inodesin = vec![0; self.treelevels];
        self.symbolsin = vec![0; self.treelevels];
        self.tree = vec![Vec::new(); self.treelevels];
        self.treelevels -= 1;
        self.symbol_size = 1;

        for i in 0..=self.treelevels {
            //let byte = reader.bytes().next().unwrap_or(Ok(0)).unwrap();
            reader.read_exact(&mut buffer)?;
            self.symbolsin[i] = buffer[0];
            self.symbol_size += self.symbolsin[i] as usize;
        }

        self.total_read += self.treelevels as usize;

        if self.symbol_size > 256 {
            return Err(anyhow!("Bad symbol table"));
        }

        self.symbolsin[self.treelevels as usize] += 1;

        for i in 0..=self.treelevels {
            let mut symbol = Vec::new();
            for _ in 0..self.symbolsin[i as usize] {
                reader.read_exact(&mut buffer)?;
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

    fn decode<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<()> {
        let mut level = 0;
        let mut code = 0;
        let mut buffer = [0; 1];
        let mut symbol;
        let mut inlevelindex;
        let treelens: Vec<usize> = self.tree.iter().map(|l| l.len()).collect();

        while self.total_read < self.size {
            reader.read_exact(&mut buffer)?;
            self.total_read += 1;
            for i in (0..=7).rev() {
                code = (code << 1) | ((buffer[0] >> i) & 1);
                if code >= self.inodesin[level] {
                    inlevelindex = (code - self.inodesin[level]) as usize;
                    if inlevelindex > self.symbolsin[level] as usize {
                        return Err(anyhow!("Invalid file format: Invalid level index"));
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
                        return Err(anyhow!("Invalid file format: tree level too big."));
                    }
                }
            }
        }
        Ok(())
    }
}

pub fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    size: usize,
) -> Result<()> {
    let mut decompressor = HuffmanDecompressor::new();
    decompressor.decompress_stream(reader, writer, size)?;
    Ok(())
}
