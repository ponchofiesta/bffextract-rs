//! bffextract CLI tool to extract or list content of BFF files (Backup File Format).

mod bff;
mod error;
mod huffman;
mod util;
pub mod io;

use crate::bff::get_record_listing;
use crate::error::{BffError, BffExtractError, BffReadError};
use bff::{open_bff_file, Record, RecordDiff};
use clap::Parser;
use comfy_table::{presets, CellAlignment, Row, Table};
use util::compare_records;
use std::io::{ErrorKind, Read, Seek};
use std::path::PathBuf;
#[cfg(not(windows))]
use users::{Groups, Users, UsersCache};

/// Definition of command line arguments
#[derive(Parser, Debug)]
#[command(about, version, author)]
struct Args {
    #[arg(help = "Path to BFF file.")]
    filename: PathBuf,

    #[arg(value_delimiter = ' ', num_args = 0.., help = "Extract specific source file(s) and folders recursively only.")]
    file_list: Vec<PathBuf>,

    #[arg(short = 'C', long, default_value = ".", help = "Extract to directory.")]
    chdir: PathBuf,

    #[arg(
        short = 't',
        long,
        default_value_t = false,
        help = "List content of BFF archive."
    )]
    list: bool,

    #[arg(short = 'd', long, help = "Compare BFF file with another one.")]
    diff: Option<PathBuf>,

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
fn print_content<I>(records: I, numeric: bool)
where
    I: IntoIterator<Item = Record>,
{
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
    for record in records {
        let username = if numeric {
            format!("{}", record.uid)
        } else {
            user_data
                .get_username_by_uid(record.uid)
                .unwrap_or(format!("{}", record.uid))
        };

        let groupname = if numeric {
            format!("{}", record.gid)
        } else {
            user_data
                .get_groupname_by_gid(record.gid)
                .unwrap_or(format!("{}", record.gid))
        };

        table.add_row(vec![
            format!("{}", record.mode),
            username,
            groupname,
            format!("{}", record.size),
            record.mdate.format(date_format).to_string(),
            record.filename.to_string_lossy().to_string(),
        ]);
    }

    println!("{table}");
}

/// Extract all selected records
fn extract_records<R, I>(reader: &mut R, records: I, args: &Args) -> Result<(), BffError>
where
    R: Read + Seek,
    I: IntoIterator<Item = Record>,
{
    for record in records {
        match record.extract_file(reader, &args.chdir, args.verbose) {
            // TODO: Error handling should be opimized
            Err(e) => {
                match e {
                    BffError::BffReadError(ref read_error) => {
                        match read_error {
                            BffReadError::IoError(io_error) => {
                                if io_error.kind() == ErrorKind::UnexpectedEof {
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

    Ok(())
}

/// Print the differences of two files
fn print_diff(diffs: &[RecordDiff]) {
    for diff in diffs {
        print!("{}", diff);
    }
}

fn main() -> Result<(), BffError> {
    let args = Args::parse();

    let file_filter = |record: &Record| {
        args.file_list.is_empty()
            || args
                .file_list
                .iter()
                .any(|inc_path| record.filename.starts_with(inc_path))
    };

    let (mut reader, _) = open_bff_file(&args.filename)?;

    let records: Vec<_> = get_record_listing(&mut reader)
        .filter(&file_filter)
        .collect();

    if records.len() == 0 && args.diff.is_none() {
        println!("No records found matching criterias.");
        return Ok(());
    }

    if args.list {
        // Print content of a file
        print_content(records, args.numeric);
    } else if args.diff.is_some() {
        // Print the differences of two files
        let (mut reader_diff, _) = open_bff_file(args.diff.unwrap())?;
        let records_diff: Vec<_> = get_record_listing(&mut reader_diff)
            .filter(&file_filter)
            .collect();
        let diffs = compare_records(&mut reader, &records, &mut reader_diff, &records_diff)?;
        print_diff(&diffs);
    } else {
        // Extract a file
        extract_records(&mut reader, records, &args)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_without_specifc() {
        let args = Args::parse_from(["", "source"]);
        assert!(args.filename.to_string_lossy() == "source");
        assert!(args.file_list.is_empty());
    }

    #[test]
    fn source_with_one_specific() {
        let args = Args::parse_from(["", "source", "specific1"]);
        assert!(args.filename.to_string_lossy() == "source");
        assert!(args.file_list.len() == 1);
        assert!(args.file_list[0].to_string_lossy() == "specific1");
    }

    #[test]
    fn source_with_three_specific() {
        let args = Args::parse_from(["", "source", "one", "two", "three"]);
        assert!(args.filename.to_string_lossy() == "source");
        assert!(args.file_list.len() == 3);
        assert!(
            args.file_list
                == [
                    PathBuf::from("one"),
                    PathBuf::from("two"),
                    PathBuf::from("three")
                ]
        );
    }

    #[test]
    fn source_with_three_specific_and_list() {
        let args = Args::parse_from(["", "-t", "source", "one", "two", "three"]);
        assert!(args.filename.to_string_lossy() == "source");
        assert!(args.file_list.len() == 3);
        assert!(
            args.file_list
                == [
                    PathBuf::from("one"),
                    PathBuf::from("two"),
                    PathBuf::from("three")
                ]
        );
        assert!(args.list);
    }
}
