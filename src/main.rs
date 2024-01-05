mod bff;
mod huffman;
mod util;

use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::io::SeekFrom;
use std::{
    fs::File,
    io::{Read, Seek},
    path::Path,
};

#[derive(Parser, Debug)]
#[command(
    name = "BFFextract",
    about = "Extract content of BFF file (AIX Backup file format)."
)]
struct Args {
    #[arg(help = "Extract to directory.")]
    filename: String,

    #[arg(short = 'C', long, default_value_t, help = "Path to BFF file.")]
    chdir: String,
}

impl Default for Args {
    fn default() -> Self {
        let path = std::env::current_dir()
            .unwrap()
            .into_os_string()
            .into_string()
            .unwrap();
        Self {
            filename: Default::default(),
            chdir: path,
        }
    }
}

/// Extract single file from stream to target directory.
fn extract_file<R: Read + Seek, P: AsRef<Path>>(reader: &mut R, out_dir: P) -> Result<()> {
    let record_header: bff::RecordHeader = util::read_struct(reader)?;
    let filename = bff::read_aligned_string(reader)?;
    let _record_trailer: bff::RecordTrailer = util::read_struct(reader)?;

    if record_header.size > 0 {
        let decompress = record_header.magic == bff::HUFFMAN_MAGIC;
        bff::extract_record(
            reader,
            &filename,
            record_header.compressed_size as usize,
            decompress,
            out_dir,
        )?;
    } else {
        // TODO: Extract empty folder
        eprintln!("Unimplemented: '{filename}' has zero size and will not be extracted.");
    }

    let aligned_up = (record_header.compressed_size + 7) & !7;
    reader.seek(SeekFrom::Current(
        (aligned_up - record_header.compressed_size) as i64,
    ))?;

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut reader = File::open(&args.filename)
        .with_context(|| format!("Failed to open input file {0}.", &args.filename))?;
    if reader.metadata().unwrap().len() > 0xffffffff {
        return Err(anyhow!("Filesize to big. Files must by up to 4 GB big."));
    }
    let file_header: bff::FileHeader = util::read_struct(&mut reader)?;
    // println!("{}", size_of::<bff::FileHeader>());
    if file_header.magic != bff::FILE_MAGIC {
        bail!("Invalid file format: magic not found.");
    }
    while let Ok(_) = extract_file(&mut reader, &args.chdir) {}

    Ok(())
}
