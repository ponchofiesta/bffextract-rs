//! [![github]](https://github.com/ponchofiesta/bffextract-rs)&ensp;[![crates-io]](https://crates.io/crates/bffextract)&ensp;[![docs-rs]](https://docs.rs/bffextract)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! <br>
//!
//! bffextract CLI tool to extract or list content of BFF files (Backup File Format).

use bfflib::archive::{Archive, Record};
use bfflib::attribute;
use bfflib::{Error, Result};
use clap::Parser;
use comfy_table::{presets, CellAlignment, Row, Table};
use core::result::Result as StdResult;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::{
    fs::File,
    io::{Read, Seek},
};
#[cfg(unix)]
use users::{Groups, Users, UsersCache};

/// Parse command line argument for attributes
fn parse_attributes(value: &str) -> StdResult<u8, String> {
    value
        .chars()
        .try_fold(attribute::ATTRIBUTE_NONE, |acc, ch| {
            #[cfg(unix)]
            match ch {
                'n' => Ok(acc | attribute::ATTRIBUTE_NONE),
                'p' => Ok(acc | attribute::ATTRIBUTE_PERMISSIONS),
                'o' => Ok(acc | attribute::ATTRIBUTE_OWNERS),
                't' => Ok(acc | attribute::ATTRIBUTE_TIMESTAMPS),
                _ => return Err(format!("Invalid attribute '{ch}'.")),
            }
            #[cfg(windows)]
            match ch {
                'n' => Ok(acc | attribute::ATTRIBUTE_NONE),
                't' => Ok(acc | attribute::ATTRIBUTE_TIMESTAMPS),
                _ => return Err(format!("Invalid attribute '{ch}'.")),
            }
        })
}

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
        short = 'A',
        long,
        default_value = "t",
        value_parser = parse_attributes,
        help = concat!("Restore only specified file attributes.\n",
               "Possible values: p = permissions (unix only)\n",
               "                 o = owners (unix only)\n",
               "                 t = timestamps\n")
    )]
    attributes: u8,

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
#[cfg(unix)]
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
#[cfg(unix)]
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
fn print_content<R: Read + Seek, P: AsRef<Path>>(
    archive: &mut Archive<R>,
    filter_list: &[P],
    numeric: bool,
) {
    let date_format = "%Y-%m-%d %H:%M:%S";
    let mut table = Table::new();
    table.set_header(Row::from(vec![
        "Mode", "UID", "GID", "Size", "Modified", "Filename",
    ]));
    // Disable all table borders
    table.load_preset(presets::NOTHING);
    // Set columns right aligned
    [1, 2, 3].iter().for_each(|&col| {
        table
            .column_mut(col)
            .unwrap()
            .set_cell_alignment(CellAlignment::Right)
    });

    let user_data = UserData::new();
    let records: Vec<&Record> = archive
        .records()
        .iter()
        .filter(|record| {
            filter_list.is_empty()
                || filter_list
                    .iter()
                    .any(|inc_path| record.filename().starts_with(inc_path))
        })
        .map(|&record| record)
        .collect();
    for record in records {
        let username = if numeric {
            format!("{}", record.uid())
        } else {
            user_data
                .get_username_by_uid(record.uid())
                .unwrap_or(format!("{}", record.uid()))
        };

        let groupname = if numeric {
            format!("{}", record.gid())
        } else {
            user_data
                .get_groupname_by_gid(record.gid())
                .unwrap_or(format!("{}", record.gid()))
        };

        let filename = record.filename().to_string_lossy().to_string();
        let print_filename = match record.symlink() {
            Some(symlink) => format!("{} -> {}", filename, symlink.display()),
            None => filename,
        };

        table.add_row(vec![
            format!("{}", record.mode()),
            username,
            groupname,
            format!("{}", record.size()),
            record.mdate().format(date_format).to_string(),
            print_filename,
        ]);
    }

    println!("{table}");
}

/// Extract all selected records
fn extract_records<R, P, D>(
    archive: &mut Archive<R>,
    filter_list: &[P],
    destination: D,
    attributes: u8,
    verbose: bool,
) -> Result<()>
where
    R: Read + Seek,
    P: AsRef<Path>,
    D: AsRef<Path>,
{
    archive.extract_when_with_attr(&destination, attributes, |inner_record| {
        let take = filter_list.is_empty()
            || filter_list
                .iter()
                .any(|inc_path| inner_record.filename().starts_with(inc_path));
        if take && verbose {
            println!("{}", inner_record.filename().display());
        }
        take
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    let reader = File::open(&args.filename)?;
    if reader.metadata().unwrap().len() > 0xffffffff {
        return Err(Error::FileToBig);
    }
    let reader = BufReader::new(reader);
    let mut archive = Archive::new(reader)?;

    if args.list {
        print_content(&mut archive, &args.file_list, args.numeric);
    } else {
        extract_records(
            &mut archive,
            &args.file_list,
            args.chdir,
            args.attributes,
            args.verbose,
        )?;
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

    #[test]
    fn source_with_attribute_timestamps() {
        let args = Args::parse_from(["", "source", "-A", "t"]);
        assert_eq!(args.filename.to_string_lossy(), "source");
        assert_eq!(args.attributes, attribute::ATTRIBUTE_TIMESTAMPS);
    }

    #[cfg(unix)]
    #[test]
    fn source_with_attributes_timestamp_and_owner() {
        let args = Args::parse_from(["", "source", "-A", "to"]);
        assert_eq!(args.filename.to_string_lossy(), "source");
        assert_eq!(
            args.attributes,
            attribute::ATTRIBUTE_OWNERS | attribute::ATTRIBUTE_TIMESTAMPS
        );
    }

    #[test]
    fn source_with_attributes_none() {
        let args = Args::parse_from(["", "source", "-A", "n"]);
        assert_eq!(args.filename.to_string_lossy(), "source");
        assert_eq!(args.attributes, attribute::ATTRIBUTE_NONE);
    }
}
