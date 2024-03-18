pub mod bff;
pub mod error;
pub mod huffman;
pub mod util;

use crate::bff::{extract_file, get_record_listing, read_file_header};
use crate::error::{BffError, BffExtractError, BffReadError};
use crate::util::UserData;
use clap::Parser;
use comfy_table::{presets, CellAlignment, Row, Table};
#[cfg(unix)]
use file_mode::ModePath;
use std::io::{self, BufReader};
use std::{
    fs::File,
    io::{Read, Seek},
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

    let user_data = UserData::new();
    get_record_listing(reader).for_each(|item| {
        let username = if numeric {
            format!("{}", item.uid)
        } else {
            user_data
                .get_username_by_uid(item.uid)
                .unwrap_or(format!("{}", item.uid))
        };
        
        let groupname = if numeric {
            format!("{}", item.gid)
        } else {
            user_data
                .get_groupname_by_gid(item.gid)
                .unwrap_or(format!("{}", item.gid))
        };

        table.add_row(vec![
            format!("{}", item.mode),
            username,
            groupname,
            format!("{}", item.size),
            item.mdate.format(date_format).to_string(),
            item.filename,
        ]);
    });

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
        print_content(&mut reader, args.numeric);
    } else {
        let records: Vec<_> = get_record_listing(&mut reader).collect();
        for record in records {
            match extract_file(&mut reader, record, &args.chdir, args.verbose) {
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
                            BffExtractError::ModeError(_mode_error) => eprintln!("{e}"),
                        },
                        BffError::MissingParentDir(ref _path) => eprintln!("{e}"),
                    }
                }
                _ => (),
            }
        }
    }

    Ok(())
}
