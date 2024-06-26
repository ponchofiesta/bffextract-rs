//! [![github]](https://github.com/ponchofiesta/bffextract-rs)&ensp;[![crates-io]](https://crates.io/crates/bfflib)&ensp;[![docs-rs]](https://docs.rs/bfflib)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! <br>
//!
//! # Examples
//! 
//! Open an archive file:
//! 
//! ```rust
//! use std::{fs::File, io::BufReader};
//! use bfflib::{attribute, archive::Archive, Result};
//! 
//! fn example() -> Result<()> {
//!     // Open BFF file
//!     let file = File::open("file.bff")?;
//!     // Use BufReader for better performance
//!     let reader = BufReader::new(file);
//!     let mut archive = Archive::new(reader)?;
//! 
//!     // Print filenames of all records in the archive
//!     archive.records().iter()
//!         .for_each(|record| println!("{}", record.filename().display()));
//! 
//!     // Extract the whole archive
//!     archive.extract("output_dir")?;
//! 
//!     // Extract single file
//!     archive.extract_file_by_name("./path/file", "output_dir")?;
//! 
//!     Ok(())
//! }
//! ```

pub mod attribute;
pub mod archive;
pub mod bff;
pub mod error;
pub mod huffman;
pub mod util;

pub use error::{Error, Result};