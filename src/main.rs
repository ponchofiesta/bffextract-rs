//! bffextract CLI tool to extract or list content of BFF files (Backup File Format).

pub mod bff;
pub mod error;
pub mod huffman;
pub mod util;

use crate::bff::{extract_file, get_record_listing, read_file_header};
use crate::error::{BffError, BffExtractError, BffReadError};
use clap::Parser;
use comfy_table::{presets, CellAlignment, Row, Table};
use std::io::{self, BufReader};
use std::{
    fs::File,
    io::{Read, Seek},
};
#[cfg(not(windows))]
use users::{Groups, Users, UsersCache};

/// Definition of command line arguments
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

/// Helper to implement different user data retrivals by target OS.
#[cfg(windows)]
struct UserData;

/// Helper to implement different user data retrivals by target OS.
#[cfg(not(windows))]
struct UserData {
    cache: UsersCache,
}

/// On non-Windows return the UNIX specific user data. On Windows always return `None`.
#[cfg(windows)]
impl UserData {
    pub fn new() -> Self {
        Self
    }

    pub fn get_username_by_uid(&self, _uid: u32) -> Option<String> {
        None
    }

    #[cfg(windows)]
    pub fn get_groupname_by_gid(&self, _gid: u32) -> Option<String> {
        None
    }
}

/// On non-Windows return the UNIX specific user data. On Windows always return `None`.
#[cfg(not(windows))]
impl UserData {
    pub fn new() -> Self {
        Self {
            cache: UsersCache::new(),
        }
    }

    pub fn get_username_by_uid(&self, uid: u32) -> Option<String> {
        self.cache
            .get_user_by_uid(uid)
            .and_then(|user| user.name().to_os_string().into_string().ok())
    }

    pub fn get_groupname_by_gid(&self, gid: u32) -> Option<String> {
        self.cache
            .get_group_by_gid(gid)
            .and_then(|group| group.name().to_os_string().into_string().ok())
    }
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
                // TODO: Error handling should be opimized
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
