mod bff;
mod huffman;
mod util;

use bff::{read_file_header, BffError, BffExtractError, BffReadError};
use clap::Parser;
use comfy_table::{presets, CellAlignment, Row, Table};
use filetime::{set_file_times, FileTime};
use normalize_path::NormalizePath;
use std::io::{self, BufReader, SeekFrom};
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

    #[arg(short = 'C', long, default_value = ".", help = "Path to BFF file.")]
    chdir: String,

    #[arg(
        short = 't',
        long,
        default_value_t = false,
        help = "List content of BFF archive."
    )]
    list: bool,

    #[arg(
        short = 'v',
        long,
        default_value_t = false,
        help = "Displays details while extracting."
    )]
    verbose: bool,
}

/// Extract single file from stream to target directory.
fn extract_file<R: Read + Seek, P: AsRef<Path>>(
    reader: &mut R,
    out_dir: P,
    verbose: bool,
) -> Result<(), BffError> {
    let record_header: bff::RecordHeader =
        util::read_struct(reader).map_err(|err| BffReadError::IoError(err))?;
    if !bff::HEADER_MAGICS
        .iter()
        .any(|magic| *magic == record_header.magic)
    {
        let magic = record_header.magic;
        return Err(BffReadError::InvalidRecordMagic(magic).into());
    }
    let filename = bff::read_aligned_string(reader).map_err(|err| BffReadError::IoError(err))?;
    let _record_trailer: bff::RecordTrailer =
        util::read_struct(reader).map_err(|err| BffReadError::IoError(err))?;

    if record_header.size > 0 {
        // File record

        // Create base directories
        let target_path = out_dir.as_ref().join(&filename).normalize();
        let target_dir = target_path.parent().ok_or(BffError::MissingParentDir(
            target_path.display().to_string(),
        ))?;
        if !target_dir.exists() {
            std::fs::create_dir_all(target_dir).map_err(|err| BffExtractError::IoError(err))?;
        }

        let decompress = record_header.magic == bff::HUFFMAN_MAGIC;

        if verbose {
            println!("{}", target_path.display());
        }

        bff::extract_record(
            reader,
            &filename,
            record_header.compressed_size as usize,
            decompress,
            &target_path,
        )?;
        set_file_times(
            &target_path,
            FileTime::from_unix_time(record_header.atime as i64, 0),
            FileTime::from_unix_time(record_header.mtime as i64, 0),
        )
        .map_err(|err| BffExtractError::IoError(err))?;
    } else {
        // TODO: Extract empty folder
        eprintln!("Unimplemented: '{filename}' has zero size and will not be extracted.");
    }

    let aligned_up = (record_header.compressed_size + 7) & !7;
    reader
        .seek(SeekFrom::Current(
            (aligned_up - record_header.compressed_size) as i64,
        ))
        .map_err(|err| BffReadError::IoError(err))?;

    Ok(())
}

/// Print content of BFF file for CLI output
fn print_content<R: Read + Seek>(reader: &mut R) {
    let date_format = "%Y-%m-%d %H:%M:%S";
    let mut table = Table::new();
    table.set_header(Row::from(vec![
        "UID", "GID", "Size", "Modified", "Filename",
    ]));
    table.load_preset(presets::NOTHING);
    let user_data = util::UserData::new();
    bff::get_record_listing(reader).for_each(|item| {
        table.add_row(vec![
            user_data.get_username_by_uid(item.uid).unwrap_or(format!("{}", item.uid)),
            user_data.get_groupname_by_gid(item.gid).unwrap_or(format!("{}", item.gid)),
            format!("{}", item.size),
            item.mdate.format(date_format).to_string(),
            item.filename,
        ]);
    });
    table
        .column_mut(0)
        .unwrap()
        .set_cell_alignment(CellAlignment::Right);
    table
        .column_mut(1)
        .unwrap()
        .set_cell_alignment(CellAlignment::Right);
    table
        .column_mut(2)
        .unwrap()
        .set_cell_alignment(CellAlignment::Right);
    println!("{table}");
}

fn main() -> Result<(), BffError> {
    let args = Args::parse();

    let reader = File::open(&args.filename).map_err(|err| BffReadError::IoError(err))?;
    if reader.metadata().unwrap().len() > 0xffffffff {
        return Err(BffReadError::FileToBig.into());
    }
    let mut reader = BufReader::new(reader);
    read_file_header(&mut reader)?;

    if args.list {
        print_content(&mut reader);
    } else {
        loop {
            match extract_file(&mut reader, &args.chdir, args.verbose) {
                Err(e) => {
                    match e {
                        BffError::BffReadError(ref read_error) => {
                            match read_error {
                                BffReadError::IoError(io_error) => {
                                    if io_error.kind() == io::ErrorKind::UnexpectedEof {
                                        // Hopefully not unexpected EOF
                                        return Ok(());
                                    } else {
                                        return Err(e);
                                    }
                                }
                                BffReadError::EmptyFilename => eprintln!("{read_error}"),
                                BffReadError::InvalidRecordMagic(_magic) => (),
                                _ => return Err(e),
                            }
                        }
                        BffError::BffExtractError(ref extract_error) => match extract_error {
                            BffExtractError::IoError(_io_error) => return Err(e),
                        },
                        BffError::MissingParentDir(ref _path) => eprintln!("{e}"),
                    }
                }
                _ => (),
            };
        }
    }

    Ok(())
}
