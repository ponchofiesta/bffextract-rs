mod bff;
mod error;
mod huffman;
mod util;

use bff::get_record_listing;
use clap::Parser;
use comfy_table::{presets, CellAlignment, Row, Table};
use file_mode::FileType;
#[cfg(unix)]
use file_mode::ModePath;
use filetime::{set_file_times, FileTime};
use normalize_path::NormalizePath;
use std::io::{self, BufReader};
use std::{
    fs::File,
    io::{Read, Seek},
    path::Path,
};

#[derive(Parser, Debug)]
#[command(about, version, author)]
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

    #[arg(
        short = 'n',
        long,
        default_value_t = false,
        help = "List numeric user and group IDs."
    )]
    numeric: bool,
}

/// Extract single file from stream to target directory.
fn extract_file<R: Read + Seek, P: AsRef<Path>>(
    reader: &mut R,
    record: bff::Record,
    out_dir: P,
    verbose: bool,
) -> Result<(), error::BffError> {
    let target_path = out_dir.as_ref().join(&record.filename).normalize();

    if let Some(path) = target_path.to_str() {
        if path == "" {
            return Ok(());
        }
    }

    if verbose {
        println!("{}", target_path.display());
    }

    match record.mode.file_type() {
        Some(FileType::Directory) => {
            if !target_path.exists() {
                std::fs::create_dir_all(&target_path)
                    .map_err(|err| error::BffExtractError::IoError(err))?;
            }
        }
        _ => {
            let target_dir = target_path
                .parent()
                .ok_or(error::BffError::MissingParentDir(
                    target_path.display().to_string(),
                ))?;
            if !target_dir.exists() {
                std::fs::create_dir_all(&target_dir)
                    .map_err(|err| error::BffExtractError::IoError(err))?;
            }

            bff::extract_record(reader, &record, &target_path)?;
        }
    }

    set_file_times(
        &target_path,
        FileTime::from_unix_time(record.adate.timestamp(), 0),
        FileTime::from_unix_time(record.mdate.timestamp(), 0),
    )
    .map_err(|err| error::BffExtractError::IoError(err))?;

    #[cfg(unix)]
    target_path
        .as_path()
        .set_mode(record.mode.mode())
        .map_err(|err| error::BffExtractError::ModeError(Box::new(err)))?;

    Ok(())
}

/// Print content of BFF file for CLI output
fn print_content<R: Read + Seek>(reader: &mut R, numeric: bool) {
    let date_format = "%Y-%m-%d %H:%M:%S";
    let mut table = Table::new();
    table.set_header(Row::from(vec![
        "Mode", "UID", "GID", "Size", "Modified", "Filename",
    ]));
    table.load_preset(presets::NOTHING);
    table
        .column_mut(1)
        .unwrap()
        .set_cell_alignment(CellAlignment::Right);
    table
        .column_mut(2)
        .unwrap()
        .set_cell_alignment(CellAlignment::Right);
    table
        .column_mut(3)
        .unwrap()
        .set_cell_alignment(CellAlignment::Right);

    let user_data = util::UserData::new();
    bff::get_record_listing(reader).for_each(|item| {
        table.add_row(vec![
            format!("{}", item.mode),
            if numeric {
                format!("{}", item.uid)
            } else {
                user_data
                    .get_username_by_uid(item.uid)
                    .unwrap_or(format!("{}", item.uid))
            },
            if numeric {
                format!("{}", item.gid)
            } else {
                user_data
                    .get_groupname_by_gid(item.gid)
                    .unwrap_or(format!("{}", item.gid))
            },
            format!("{}", item.size),
            item.mdate.format(date_format).to_string(),
            item.filename,
        ]);
    });

    println!("{table}");
}

fn main() -> Result<(), error::BffError> {
    let args = Args::parse();

    let reader = File::open(&args.filename).map_err(|err| error::BffReadError::IoError(err))?;
    if reader.metadata().unwrap().len() > 0xffffffff {
        return Err(error::BffReadError::FileToBig.into());
    }
    let mut reader = BufReader::new(reader);
    bff::read_file_header(&mut reader)?;

    if args.list {
        print_content(&mut reader, args.numeric);
    } else {
        let records: Vec<_> = get_record_listing(&mut reader).collect();
        for record in records {
            match extract_file(&mut reader, record, &args.chdir, args.verbose) {
                Err(e) => {
                    match e {
                        error::BffError::BffReadError(ref read_error) => {
                            match read_error {
                                error::BffReadError::IoError(io_error) => {
                                    if io_error.kind() == io::ErrorKind::UnexpectedEof {
                                        // Hopefully not unexpected EOF
                                        return Ok(());
                                    } else {
                                        return Err(e);
                                    }
                                }
                                error::BffReadError::EmptyFilename => eprintln!("{read_error}"),
                                error::BffReadError::InvalidRecordMagic(_magic) => (),
                                _ => return Err(e),
                            }
                        }
                        error::BffError::BffExtractError(ref extract_error) => {
                            match extract_error {
                                error::BffExtractError::IoError(_io_error) => return Err(e),
                                error::BffExtractError::ModeError(_mode_error) => eprintln!("{e}"),
                            }
                        }
                        error::BffError::MissingParentDir(ref _path) => eprintln!("{e}"),
                    }
                }
                _ => (),
            }
        }
    }

    Ok(())
}
