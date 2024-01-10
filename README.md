# BFFextract

Simple Rust program to extract AIX BFF files.

## Usage

```
Extract content of BFF file (AIX Backup file format).

Usage: bffextract.exe [OPTIONS] <FILENAME>

Arguments:
  <FILENAME>  Extract to directory.

Options:
  -C, --chdir <CHDIR>  Path to BFF file. [default: .]
  -t, --list           List content of BFF archive.
  -v, --verbose        Displays details while extracting.
  -h, --help           Print help
```

## Limitations

- Folders are not extracted. Currently only files are extracted and their parent folders are created implicitly.
  - Therefore modified date is not set to folders.
- Checksum is not verified.
- Owner and Group gets read but actually is not set to extracted files.
- Bad file format may be ignored in some cases.

## Credits

Based on:

- https://github.com/terorie/aix-bff-go
- https://github.com/ReFirmLabs/binwalk/blob/cddfede795971045d99422bd7a9676c8803ec5ee/src/binwalk/magic/archives#L226
- https://github.com/jtreml/firmware-mod-kit/blob/master/src/bff
