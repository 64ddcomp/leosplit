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
- **MFS Binary Extraction**: Traverses 64DD MFS directory entries and carves exact byte ranges from `.ndd` images
- **Manifest Binary Extraction**: Still supports generated manifests for load-table based workflows
- **LeoSplit Assembly Workspace**: Emits raw bins, MIPS assembly listings, symbol hints, rebuild metadata, and build scaffolding
- **Exact Image Rebuilds**: Reconstructs an `.ndd` from split bins and compares SHA-1 against the original

## Usage

Install for local development:

```bash
python -m pip install -e .
```

Generate a manifest:

```bash
leosplit-manifest input.ndd -o manifest.json
```

Extract files directly from a 64DD MFS image:

```bash
leosplit-extract input.ndd -o extracted
```

List detected MFS entries without extracting:

```bash
leosplit-extract input.ndd --list
```

Extract binaries from a manifest:

```bash
leosplit-extract input.ndd manifest.json -o extracted
```

Create a Splat-like assembly workspace from the manifest:

```bash
leosplit-asm input.ndd manifest.json -o split --overwrite --verbose
```

LeoSplit infers the YAML project name and basename from known 64DD disk codes,
manifest metadata, embedded title strings, or finally the image filename. It
also emits a compiler guess with a detection reason. Override any of these when
you know better:

```bash
leosplit-asm NUD-DSCJ-JPN.ndd simcity64.json -o split-simcity --overwrite \
  --name "SimCity 64" --basename simcity64 --compiler IDO
```

Restrict disassembly when you know a specific code span:

```bash
leosplit-asm input.ndd manifest.json -o split --overwrite \
  --code-range 3:0x80280000-0x802C0000
```

This writes:
- `split/bin/*.bin`: exact carved segment bytes
- `split/asm/*.s`: big-endian MIPS assembly listings using manifest VRAM addresses
- `split/symbols/*.sym`: entry labels, branch/jump labels, and rough data boundary hints
- `split/macro.inc`: assembler compatibility macros
- `split/<basename>.ld`: a generated MIPS linker script scaffold
- `split/Makefile`: rebuild and compare targets
- `split/leosplit_workspace.json`: machine-readable rebuild metadata
- `split/leosplit.yaml`: a human-readable segment skeleton for the project

Rebuild the image from the workspace bins:

```bash
leosplit-build split -o split/build/rebuilt.ndd --base input.ndd --compare input.ndd
```

Or from inside the generated workspace:

```bash
cd split
make compare
```

The manifest includes:
- `file_id`: Unique identifier for each file entry
- `file_name`: Extracted cartridge metadata or file name
- `lba_start`: Logical block address (sector-based offset)
- `lba_length`: Length in sectors  
- `load_address`: N64 RDRAM load address (if available)
- `entry_point`: N64 program entry point (if available)

## Output Formats

- **JSON** (default): `leosplit-manifest input.ndd -o manifest.json`
- **YAML**: `leosplit-manifest input.ndd --format yaml`

The extractor accepts either generated JSON or generated YAML:

```bash
leosplit-extract NUD-DMTJ-JPN1.ndd talentstudio.json -o extracted
leosplit-extract NUD-DMTJ-JPN1.ndd talentstudio.yaml -o extracted --overwrite
```

## Example

```bash
# Generate JSON manifest
leosplit-manifest NUD-DMTJ-JPN1.ndd -o manifest.json

# Output YAML to stdout
leosplit-manifest input.ndd --format yaml

# Verbose output with parsing details
leosplit-manifest input.ndd --verbose

# Extract files and print offsets/load addresses
leosplit-extract input.ndd manifest.json -o extracted --verbose

# Build a decompilation workspace with asm and symbol hints
leosplit-asm input.ndd manifest.json -o split --overwrite --verbose

# Rebuild and compare the image from split bins
leosplit-build split -o split/build/rebuilt.ndd --base input.ndd --compare input.ndd
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

3. **Direct MFS Extraction**: Reads 64DD MFS directory entries
   - Uses the real zone-dependent `.ndd` LBA map for full 64DD images
   - Applies each entry's start LBA, intra-block offset, and byte-exact file size
   - Writes carved files using their MFS name/type metadata

4. **Manifest Extraction**: Reads each manifest entry
   - Uses the real `.ndd` LBA map for full 64DD images, or fixed sectors for test images
   - Reads `lba_length` blocks unless a byte-exact `file_size` is present
   - Writes the result as a standalone `.bin`

5. **Assembly Workspace Generation**: Uses manifest load metadata as segment hints
   - Treats each carved file as a loaded N64 MIPS segment
   - Infers project name/basename from disk code, embedded strings, manifest data, or filename
   - Detects obvious compiler markers, otherwise records the N64/N64DD IDO default assumption
   - Disassembles words using big-endian MIPS decoding
   - Accepts explicit code ranges by file ID, manifest name, or generated segment name
   - Labels entry points and local branch/jump targets
   - Emits comments for possible data boundaries such as string regions and long zero runs

6. **Workspace Rebuilds**: Uses generated workspace metadata
   - Patches `bin/*.bin` back into a base image at the original ROM offsets
   - Rejects segment size mismatches by default
   - Can compare rebuilt output against the original image by SHA-1
   - Generates `macro.inc`, `<basename>.ld`, and `Makefile` so the workspace can grow into a self-contained decomp project

## Testing

```bash
python -m pytest
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
