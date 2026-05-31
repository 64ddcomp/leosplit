#!/usr/bin/env python3
"""Generate a 64DD .ndd manifest for Leo decompilation workflows."""

import argparse
import json
import math
import os
import re
import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

SECTOR_SIZE_DEFAULT = 2048
RDRAM_MIN = 0x80000000
RDRAM_MAX = 0x80800000
MAX_REASONABLE_LBA = 0x10000
MAX_REASONABLE_LBA_LENGTH = 0x4000
LOAD_TABLE_SCAN_LIMIT = 0x800000
UNHELPFUL_LABELS = {"DELETED", "NULL", "NONE", "BREAKPOINT"}


@dataclass
class ManifestEntry:
    file_id: int
    file_name: str
    lba_start: int
    lba_length: int
    load_address: int
    entry_point: int
    offset: int
    size: int


def read_be_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def is_valid_rdram(addr: int) -> bool:
    return RDRAM_MIN <= addr < RDRAM_MAX


def format_hex(value: int) -> str:
    return f"0x{value:08X}"


def sanitize_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name.strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "unnamed"


def find_nearby_label(data: bytes, offset: int, search_back: int = 512) -> Optional[str]:
    start = max(0, offset - search_back)
    region = data[start:offset]
    matches = list(re.finditer(rb"[A-Za-z0-9_./:-]{6,48}\x00?", region))
    for match in reversed(matches):
        label = match.group(0).rstrip(b"\x00")
        if label and not all(byte == label[0] for byte in label):
            cleaned = sanitize_name(label.decode("ascii", errors="replace"))
            if cleaned.upper() not in UNHELPFUL_LABELS:
                return cleaned
    return None


def parse_dol_header(data: bytes, offset: int) -> Optional[Dict[str, Any]]:
    if offset + 0x100 > len(data):
        return None

    # DOL header fields are big-endian.
    text_offsets = [read_be_u32(data, offset + i * 4) for i in range(7)]
    data_offsets = [read_be_u32(data, offset + 0x1C + i * 4) for i in range(11)]
    text_addresses = [read_be_u32(data, offset + 0x4C + i * 4) for i in range(7)]
    data_addresses = [read_be_u32(data, offset + 0x70 + i * 4) for i in range(11)]
    text_sizes = [read_be_u32(data, offset + 0xA0 + i * 4) for i in range(7)]
    data_sizes = [read_be_u32(data, offset + 0xC0 + i * 4) for i in range(11)]
    bss_address = read_be_u32(data, offset + 0xF0)
    bss_size = read_be_u32(data, offset + 0xF4)
    entry_point = read_be_u32(data, offset + 0xF8)

    # A DOL must have a valid entry point and at least one non-zero load address.
    if entry_point == 0 or not is_valid_rdram(entry_point):
        return None

    load_addresses = [addr for addr in text_addresses + data_addresses if addr != 0]
    if not load_addresses or not any(is_valid_rdram(addr) for addr in load_addresses):
        return None

    required_size = 0
    for file_offset, size in zip(text_offsets + data_offsets, text_sizes + data_sizes):
        if size == 0:
            continue
        if file_offset < 0 or file_offset + size > len(data):
            return None
        required_size = max(required_size, file_offset + size)

    if required_size == 0:
        return None

    # Validate that offsets correspond to a contiguous file area inside the image.
    if offset + required_size > len(data):
        return None

    return {
        "entry_point": entry_point,
        "load_address": min([addr for addr in load_addresses if is_valid_rdram(addr)]),
        "file_size": required_size,
        "text_addresses": text_addresses,
        "data_addresses": data_addresses,
    }


def find_n64dd_load_table_entries(
    data: bytes, sector_size: int = SECTOR_SIZE_DEFAULT
) -> List[ManifestEntry]:
    """Find 64DD load-table records with real LBA and RDRAM ranges.

    Mario Artist titles keep small load descriptors inside the disk image. The
    useful part of those descriptors is:

        lba_start, lba_end, ram_start, ram_end, entry_or_init, ram_end_again

    Not every descriptor starts on the same larger record boundary, so this
    scans for that field pattern directly and then keeps only clustered hits.
    """
    raw_hits: List[Tuple[int, int, int, int, int, int]] = []
    seen_ranges = set()

    scan_limit = min(len(data), LOAD_TABLE_SCAN_LIMIT)
    for offset in range(0, scan_limit - 24, 4):
        lba_start, lba_end, load_start, load_end, entry_point, _ = struct.unpack_from(
            ">IIIIII", data, offset
        )
        if not (
            0 < lba_start < lba_end <= MAX_REASONABLE_LBA
            and (lba_end - lba_start) <= MAX_REASONABLE_LBA_LENGTH
            and is_valid_rdram(load_start)
            and is_valid_rdram(load_end)
            and load_start < load_end
        ):
            continue

        key = (lba_start, lba_end, load_start, load_end)
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        raw_hits.append((offset, lba_start, lba_end, load_start, load_end, entry_point))

    if not raw_hits:
        return []

    clusters: List[List[Tuple[int, int, int, int, int, int]]] = []
    for hit in raw_hits:
        if not clusters or hit[0] - clusters[-1][-1][0] > 0x800:
            clusters.append([hit])
        else:
            clusters[-1].append(hit)

    clustered_hits = [hit for cluster in clusters if len(cluster) >= 2 for hit in cluster]
    if not clustered_hits:
        clustered_hits = raw_hits[:1]

    sorted_hits = sorted(clustered_hits, key=lambda hit: (hit[1], hit[3], hit[0]))
    entries: List[ManifestEntry] = []
    label_counts: Dict[str, int] = {}
    for offset, lba_start, lba_end, load_start, load_end, entry_point in sorted_hits:
        label = find_nearby_label(data, offset) or f"load_table_{offset:08X}"
        label_counts[label] = label_counts.get(label, 0) + 1
        file_name = label if label_counts[label] == 1 else f"{label}_{label_counts[label]:02d}"
        safe_entry = entry_point if load_start <= entry_point < load_end else load_start

        entries.append(
            ManifestEntry(
                file_id=len(entries) + 1,
                file_name=file_name,
                lba_start=lba_start,
                lba_length=lba_end - lba_start,
                load_address=load_start,
                entry_point=safe_entry,
                offset=offset,
                size=(lba_end - lba_start) * sector_size,
            )
        )
    return entries


def find_ndd_metadata_entries(data: bytes) -> List[ManifestEntry]:
    """Parse Mario Artist 64DD metadata record format.
    
    Searches the metadata region starting at 0x1CE30 for cartridge metadata.
    Each record is 232 bytes (0xE8) and contains identifiers separated by padding.
    """
    candidates: List[ManifestEntry] = []
    METADATA_START = 0x1CE30
    RECORD_SIZE = 0xE8  # 232 bytes
    size = len(data)
    
    if METADATA_START >= size:
        return candidates
    
    file_id = 1
    seen_names = set()
    
    # Scan metadata region looking for valid identifiers
    KNOWN_CODES = [
        b'STW',
        b'SVR',
        b'BUUCTF',
        b'BUUIDX',
        b'NRMID',
    ]
    
    # Scan only the first few records to avoid false positives
    max_offset = min(METADATA_START + (RECORD_SIZE * 300), size)  # ~70KB of records
    offset = METADATA_START
    
    while offset < max_offset:
        record = data[offset:min(offset + RECORD_SIZE, size)]
        
        # Look for known code patterns in this record
        for code in KNOWN_CODES:
            pos = record.find(code)
            if pos != -1:
                # Extract identifier starting from code
                # Continue until we hit non-alphanumeric or excessive padding
                end = pos + len(code)
                u_count = 0
                while end < len(record):
                    byte_val = record[end:end+1]
                    if byte_val == b'U':
                        u_count += 1
                        if u_count >= 4:  # More than 3 U's in a row = padding start
                            break
                    else:
                        u_count = 0
                        # Continue if alphanumeric, underscore, or some punctuation
                        if byte_val.isalnum() or byte_val in b'_-.':
                            end += 1
                        else:
                            break
                    end += 1
                
                # Get the extracted name
                name_bytes = record[pos:end].rstrip(b'U')  # Remove trailing U padding
                if len(name_bytes) >= 9:  # Minimum valid length
                    name = name_bytes.decode('ascii', errors='replace').strip()
                    # Remove any control characters
                    name = ''.join(c for c in name if c.isprintable())
                    if name and name not in seen_names:
                        # Validate: mostly alphanumeric
                        if sum(c.isalnum() or c in '_-.' for c in name) > len(name) * 0.7:
                            seen_names.add(name)
                            candidates.append(
                                ManifestEntry(
                                    file_id=file_id,
                                    file_name=name,
                                    lba_start=0,
                                    lba_length=0,
                                    load_address=0x80000000,
                                    entry_point=0x80000000,
                                    offset=offset + pos,
                                    size=0,
                                )
                            )
                            file_id += 1
        
        offset += RECORD_SIZE
    
    return candidates


def find_dol_candidates(data: bytes, sector_size: int) -> List[ManifestEntry]:
    candidates: List[ManifestEntry] = []
    seen_offsets = set()
    size = len(data)

    for offset in range(0, size - 0x100 + 1, 4):
        if offset % sector_size != 0:
            continue

        if offset in seen_offsets:
            continue

        header = parse_dol_header(data, offset)
        if header is None:
            continue

        file_size = header["file_size"]
        if file_size <= 0 or offset + file_size > size:
            continue

        lba_start = offset // sector_size
        lba_length = math.ceil(file_size / sector_size)
        file_id = len(candidates) + 1
        file_name = f"file_{file_id:02d}.dol"

        candidates.append(
            ManifestEntry(
                file_id=file_id,
                file_name=file_name,
                lba_start=lba_start,
                lba_length=lba_length,
                load_address=header["load_address"],
                entry_point=header["entry_point"],
                offset=offset,
                size=file_size,
            )
        )
        seen_offsets.add(offset)

    return candidates


def build_manifest(source_file: str, entries: List[ManifestEntry], sector_size: int) -> Dict[str, Any]:
    return {
        "source_file": os.path.basename(source_file),
        "sector_size": sector_size,
        "file_count": len(entries),
        "files": [
            {
                "file_id": entry.file_id,
                "file_name": entry.file_name,
                "lba_start": entry.lba_start,
                "lba_length": entry.lba_length,
                "load_address": format_hex(entry.load_address),
                "entry_point": format_hex(entry.entry_point),
            }
            for entry in entries
        ],
    }


def dump_yaml(manifest: Dict[str, Any]) -> str:
    lines: List[str] = []

    def scalar(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        text = str(value)
        if text == "" or text.strip() != text or any(ch in text for ch in ':#\n"\\'):
            return json.dumps(text)
        return text

    lines.append(f"source_file: {scalar(manifest['source_file'])}")
    lines.append(f"sector_size: {scalar(manifest['sector_size'])}")
    lines.append(f"file_count: {scalar(manifest['file_count'])}")
    lines.append("files:")
    for file_entry in manifest["files"]:
        lines.append("  - file_id: " + scalar(file_entry["file_id"]))
        lines.append("    file_name: " + scalar(file_entry["file_name"]))
        lines.append("    lba_start: " + scalar(file_entry["lba_start"]))
        lines.append("    lba_length: " + scalar(file_entry["lba_length"]))
        lines.append("    load_address: " + scalar(file_entry["load_address"]))
        lines.append("    entry_point: " + scalar(file_entry["entry_point"]))
    return "\n".join(lines)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect a 64DD .ndd image and emit a JSON/YAML file manifest."
    )
    parser.add_argument("input", help="Path to the .ndd image")
    parser.add_argument("-o", "--output", help="Output manifest file path")
    parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--sector-size",
        type=int,
        default=SECTOR_SIZE_DEFAULT,
        help="Sector size used for LBA calculations (default: 2048)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print parsing details to stderr",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 2

    with open(args.input, "rb") as f:
        data = f.read()

    # Prefer real 64DD load tables. The metadata labels found in some disk
    # system areas repeat many times and do not contain useful LBA/load fields.
    entries = find_n64dd_load_table_entries(data, args.sector_size)
    if not entries:
        entries = find_dol_candidates(data, args.sector_size)
    if not entries:
        entries = find_ndd_metadata_entries(data)
    
    manifest = build_manifest(args.input, entries, args.sector_size)

    if args.verbose:
        print(f"Parsed {len(entries)} candidate file(s)", file=sys.stderr)
        for entry in entries:
            print(
                f"  id={entry.file_id} name={entry.file_name} lba={entry.lba_start}+{entry.lba_length} "
                f"load={format_hex(entry.load_address)} entry={format_hex(entry.entry_point)}",
                file=sys.stderr,
            )

    output_text = json.dumps(manifest, indent=2) if args.format == "json" else dump_yaml(manifest)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"Wrote manifest to {args.output}")
    else:
        print(output_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
