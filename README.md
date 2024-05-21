# BFFextract

Simple Rust program to extract AIX BFF files.

## Install

### Cargo

To compile it from source you can just install it using cargo install.

```
cargo install bffextract
```

### Binary download

Each release is available in compiled binary from Github. Linux build is using MUSL toolchain to make it work on older libc versions (e.g. CentOS 7) too.

https://github.com/ponchofiesta/bffextract-rs/releases

## Usage

```
Extract content of BFF file (AIX Backup file format)

Usage: bffextract.exe [OPTIONS] <FILENAME> [FILE_LIST]...

Arguments:
  <FILENAME>      Path to BFF file.
  [FILE_LIST]...  Extract specific source file(s) and folders recursively only.

Options:
  -C, --chdir <CHDIR>  Extract to directory. [default: .]
  -t, --list           List content of BFF archive.
  -v, --verbose        Displays details while extracting.
  -n, --numeric        List numeric user and group IDs.
  -h, --help           Print help
  -V, --version        Print version
```

## Limitations

- Checksum is not verified (archive and content files).
- Owner and Group gets read but actually is not set to extracted files. (But file modes will be set)
- Symlinks are unsupported. They are not part of the BFF file format, but of the liblpp.a file which is part of a install fileset.
- Bad file format may be ignored in some cases.

## Credits

Based on:

- https://github.com/terorie/aix-bff-go
- https://github.com/ReFirmLabs/binwalk/blob/cddfede795971045d99422bd7a9676c8803ec5ee/src/binwalk/magic/archives#L226
- https://github.com/jtreml/firmware-mod-kit/blob/master/src/bff
