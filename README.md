# BFFextract

Simple Rust program to extract AIX BFF files.

## Usage

```
Extract content of BFF file (AIX Backup file format).

Usage: bffextract-rs.exe [OPTIONS] <FILENAME>        

Arguments:
  <FILENAME>  Extract to directory.

Options:
  -C, --chdir <CHDIR>  Path to BFF file. [default: ]
  -h, --help           Print help
```

## Limitations

- Decompression of compressed files is very slow.
- Empty folders are not extracted. Currently only files are extracted and their parent folders are created implicitly.
