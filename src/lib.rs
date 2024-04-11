//! [![github]](https://github.com/ponchofiesta/bffextract-rs)&ensp;[![crates-io]](https://crates.io/crates/bffextract)&ensp;[![docs-rs]](https://docs.rs/bffextract)
//! 
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//! 
//! <br>
//! 
//! `bffextract` proviedes a library and an application using it to handle and
//! extract AIX BFF files (Backup File Format).

pub mod bff;
pub mod error;
pub mod huffman;
pub mod util;
pub mod io;