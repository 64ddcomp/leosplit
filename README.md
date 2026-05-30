# leosplit

A binary splitting tool for 64DD `.ndd` images, built to assist decompilation and modding projects.

`leosplit` is intended to fill a role similar to Splat for 64DD disk images:
identify loadable binaries, record their disk/LBA and RDRAM mapping metadata,
then extract those ranges into standalone files for tools like Ghidra.

## Features

- **64DD Load Table Detection**: Finds LBA ranges paired with N64 RDRAM load/entry addresses
- **Mario Artist 64DD Metadata Fallback**: Extracts repeated disk metadata labels only when no load tables are found
- **DOL Fallback**: Automatically detects and parses GameCube DOL executable files if native metadata is not found
- **Multiple Output Formats**: JSON (default) or YAML output
- **File Identification**: Extracts cartridge file/module names and metadata
- **Binary Extraction**: Uses a generated manifest to dump each LBA range into its own `.bin` file

## Usage

Generate a manifest:

```bash
python leosplit_manifest.py input.ndd -o manifest.json
```

Extract binaries from a manifest:

```bash
python leosplit_extract.py input.ndd manifest.json -o extracted
```

The manifest includes:
- `file_id`: Unique identifier for each file entry
- `file_name`: Extracted cartridge metadata or file name
- `lba_start`: Logical block address (sector-based offset)
- `lba_length`: Length in sectors  
- `load_address`: N64 RDRAM load address (if available)
- `entry_point`: N64 program entry point (if available)

## Output Formats

- **JSON** (default): `python leosplit_manifest.py input.ndd -o manifest.json`
- **YAML**: `python leosplit_manifest.py input.ndd --format yaml`

The extractor accepts either generated JSON or generated YAML:

```bash
python leosplit_extract.py NUD-DMTJ-JPN1.ndd talentstudio.json -o extracted
python leosplit_extract.py NUD-DMTJ-JPN1.ndd talentstudio.yaml -o extracted --overwrite
```

## Example

```bash
# Generate JSON manifest
python leosplit_manifest.py NUD-DMTJ-JPN1.ndd -o manifest.json

# Output YAML to stdout
python leosplit_manifest.py input.ndd --format yaml

# Verbose output with parsing details
python leosplit_manifest.py input.ndd --verbose

# Extract files and print offsets/load addresses
python leosplit_extract.py input.ndd manifest.json -o extracted --verbose
```

Extractor output files are named with the manifest ID and sanitized file name,
for example `extracted/03_NICHIYOUBI.bin`.

## How It Works

1. **Primary Method**: Scans for 64DD load table records
   - Looks for `lba_start`, `lba_end`, `ram_start`, `ram_end`, and entry/init addresses
   - Keeps clustered records to avoid treating random data as files
   - Uses nearby ASCII labels when available, otherwise names entries by table offset
   
2. **Fallback Method**: If no metadata found, searches for embedded DOL (GameCube executable) headers
   - Validates DOL header structure
   - Extracts load address and entry point from RDRAM addresses

3. **Extraction**: Reads each manifest entry
   - Seeks to `lba_start * sector_size` in the `.ndd`
   - Reads `lba_length * sector_size` bytes
   - Writes the result as a standalone `.bin`

## Testing

```bash
python -m unittest tests.test_manifest tests.test_extract
```

## Sample Output

```json
{
  "source_file": "NUD-DMTJ-JPN1.ndd",
  "sector_size": 2048,
  "file_count": 17,
  "files": [
    {
      "file_id": 1,
      "file_name": "keyword_pmotion2",
      "lba_start": 43,
      "lba_length": 1,
      "load_address": "0x80218980",
      "entry_point": "0x802189D0"
    }
  ]
}
```
