#!/usr/bin/env python3
"""Extract files from 64DD .ndd images or leosplit manifests."""

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from leosplit_manifest import sanitize_name

SECTOR_SIZE_DEFAULT = 2048
NDD_IMAGE_SIZE = 64_458_560
MFS_ID = b"64dd-Multi"
MFS_ROM_FS_TYPE = b"02"
MFS_RAM_FS_TYPE = b"01"
MFS_VERSION = b"01"
MFS_ID_SIZE_ROM = 48
MFS_ID_SIZE_RAM = 60
MFS_FAT_SIZE = 5748
MFS_DIR_ENTRY_SIZE = 48
ROM_END_LBA_BY_DISK_TYPE = (1417, 1965, 2513, 3061, 3609, 4087, 4291)
RAM_START_LBA_BY_DISK_TYPE = (1418, 1966, 2514, 3062, 3610, 4088, None)
MAX_LBA = 4291

# Full .ndd images are stored in 64DD logical LBA order. Each tuple is
# (zone, lba_count, block_size).
NDD_LBA_ZONES: Tuple[Tuple[int, int, int], ...] = (
    (0, 268, 19720),
    (1, 292, 18360),
    (2, 274, 17680),
    (3, 274, 16320),
    (4, 274, 14960),
    (5, 274, 13600),
    (6, 274, 12240),
    (7, 204, 10880),
    (8, 204, 9520),
    (7, 274, 10880),
    (6, 274, 12240),
    (5, 274, 13600),
    (4, 274, 14960),
    (3, 274, 16320),
    (2, 292, 17680),
    (1, 292, 18360),
)


@dataclass(frozen=True)
class LbaInfo:
    lba: int
    offset: int
    size: int
    zone: int


@dataclass
class MfsVolume:
    area: str
    disk_type: int
    id_lba: int
    management_start_lba: int
    management_lba_count: int
    directory_offset: int
    directory_size: int


@dataclass
class MfsDirectoryEntry:
    entry_id: int
    area: str
    attr: int
    parent_id: int
    company_code: str
    game_code: str
    start_lba: int
    file_size: int
    name: str
    file_type: str
    data_offset: int
    entry_offset: int

    @property
    def full_name(self) -> str:
        extension = sanitize_name(self.file_type)
        name = sanitize_name(self.name)
        return f"{name}.{extension}" if extension else name


def build_ndd_lba_map() -> List[LbaInfo]:
    lbas: List[LbaInfo] = []
    offset = 0
    lba = 0
    for zone, lba_count, block_size in NDD_LBA_ZONES:
        for _ in range(lba_count):
            lbas.append(LbaInfo(lba=lba, offset=offset, size=block_size, zone=zone))
            offset += block_size
            lba += 1
    return lbas


NDD_LBA_MAP = build_ndd_lba_map()


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if value.startswith('"'):
        return json.loads(value)
    try:
        return int(value, 0)
    except ValueError:
        return value


def load_simple_yaml(text: str) -> Dict[str, Any]:
    """Load the small YAML subset emitted by leosplit_manifest.py."""
    manifest: Dict[str, Any] = {}
    current_file: Optional[Dict[str, Any]] = None

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        if raw_line == "files:":
            manifest["files"] = []
            continue
        if raw_line.startswith("  - "):
            key, value = raw_line[4:].split(":", 1)
            current_file = {key.strip(): parse_scalar(value)}
            manifest.setdefault("files", []).append(current_file)
            continue
        if raw_line.startswith("    "):
            if current_file is None:
                raise ValueError("YAML file entry field appeared before a file item")
            key, value = raw_line[4:].split(":", 1)
            current_file[key.strip()] = parse_scalar(value)
            continue
        key, value = raw_line.split(":", 1)
        manifest[key.strip()] = parse_scalar(value)

    return manifest


def load_manifest(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    try:
        manifest = json.loads(text)
    except json.JSONDecodeError:
        manifest = load_simple_yaml(text)

    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("Manifest must contain a files list")
    return manifest


def output_filename(entry: Dict[str, Any], width: int) -> str:
    file_id = int(entry["file_id"])
    file_name = sanitize_name(str(entry.get("file_name") or f"file_{file_id:02d}"))
    return f"{file_id:0{width}d}_{file_name}.bin"


def output_mfs_filename(entry: MfsDirectoryEntry, width: int) -> str:
    file_name = sanitize_name(entry.full_name)
    return f"{entry.entry_id:0{width}d}_{entry.area}_{file_name}"


def get_fixed_lba_info(lba: int, sector_size: int) -> LbaInfo:
    return LbaInfo(lba=lba, offset=lba * sector_size, size=sector_size, zone=0)


def get_lba_info(
    lba: int,
    image_size: int,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> LbaInfo:
    if image_size == NDD_IMAGE_SIZE:
        if not 0 <= lba < len(NDD_LBA_MAP):
            raise ValueError(f"LBA out of range for .ndd image: {lba}")
        return NDD_LBA_MAP[lba]
    return get_fixed_lba_info(lba, sector_size)


def read_lba(
    data: bytes,
    lba: int,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> bytes:
    info = get_lba_info(lba, len(data), sector_size)
    return data[info.offset : info.offset + info.size]


def read_lba_span(
    data: bytes,
    start_lba: int,
    lba_count: int,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> bytes:
    return b"".join(read_lba(data, start_lba + index, sector_size) for index in range(lba_count))


def lba_data_offset(
    image_size: int,
    lba: int,
    block_offset: int,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> int:
    info = get_lba_info(lba, image_size, sector_size)
    if block_offset < 0 or block_offset >= info.size:
        raise ValueError(f"Invalid offset 0x{block_offset:X} inside LBA {lba}")
    return info.offset + block_offset


def decode_text(raw: bytes, encoding: str = "shift_jis") -> str:
    raw = raw.split(b"\x00", 1)[0].rstrip(b" ")
    if not raw:
        return ""
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError:
        return raw.decode("ascii", errors="replace")


def looks_like_mfs_id(block: bytes, fs_type: bytes) -> bool:
    return (
        len(block) >= MFS_ID_SIZE_ROM
        and block[0:10] == MFS_ID
        and block[0x0A:0x0C] == fs_type
        and block[0x0C:0x0E] == MFS_VERSION
    )


def find_mfs_volumes(data: bytes, sector_size: int = SECTOR_SIZE_DEFAULT) -> List[MfsVolume]:
    volumes: List[MfsVolume] = []
    image_size = len(data)
    lba_limit = len(NDD_LBA_MAP) if image_size == NDD_IMAGE_SIZE else image_size // sector_size

    for lba in range(min(lba_limit, MAX_LBA + 1)):
        block = read_lba(data, lba, sector_size)
        if looks_like_mfs_id(block, MFS_ROM_FS_TYPE):
            disk_type = block[0x0F]
            if disk_type >= len(ROM_END_LBA_BY_DISK_TYPE):
                continue
            rom_end_lba = ROM_END_LBA_BY_DISK_TYPE[disk_type]
            management_lba_count = struct.unpack_from(">H", block, 0x28)[0]
            if management_lba_count <= 0:
                management_lba_count = rom_end_lba - lba + 1
            management_start_lba = rom_end_lba - management_lba_count + 1
            if management_start_lba <= lba <= rom_end_lba:
                volumes.append(
                    MfsVolume(
                        area="rom",
                        disk_type=disk_type,
                        id_lba=lba,
                        management_start_lba=management_start_lba,
                        management_lba_count=management_lba_count,
                        directory_offset=MFS_ID_SIZE_ROM,
                        directory_size=-1,
                    )
                )
        elif looks_like_mfs_id(block, MFS_RAM_FS_TYPE):
            disk_type = block[0x0F]
            ram_start = RAM_START_LBA_BY_DISK_TYPE[disk_type] if disk_type < 6 else None
            if ram_start is None:
                continue
            volumes.append(
                MfsVolume(
                    area="ram",
                    disk_type=disk_type,
                    id_lba=lba,
                    management_start_lba=ram_start,
                    management_lba_count=3,
                    directory_offset=MFS_ID_SIZE_RAM + MFS_FAT_SIZE,
                    directory_size=-1,
                )
            )

    return dedupe_volumes(volumes)


def dedupe_volumes(volumes: Sequence[MfsVolume]) -> List[MfsVolume]:
    seen = set()
    unique: List[MfsVolume] = []
    for volume in volumes:
        key = (volume.area, volume.management_start_lba, volume.id_lba)
        if key in seen:
            continue
        seen.add(key)
        unique.append(volume)
    return unique


def parse_mfs_directory_entry(
    raw: bytes,
    entry_id: int,
    area: str,
    entry_offset: int,
) -> Optional[MfsDirectoryEntry]:
    if len(raw) != MFS_DIR_ENTRY_SIZE or raw == b"\x00" * MFS_DIR_ENTRY_SIZE:
        return None

    attr, parent_id = struct.unpack_from(">HH", raw, 0x00)
    if attr == 0:
        return None

    start_lba = struct.unpack_from(">H", raw, 0x0A)[0]
    file_size = struct.unpack_from(">I", raw, 0x0C)[0]
    name = decode_text(raw[0x10:0x24])
    file_type = decode_text(raw[0x24:0x29], encoding="ascii")
    data_offset = struct.unpack_from(">H", raw, 0x2A)[0] if area == "rom" else 0
    company_code = decode_text(raw[0x04:0x06], encoding="ascii")
    game_code = decode_text(raw[0x06:0x0A], encoding="ascii")

    if not name or file_size == 0 or start_lba > MAX_LBA:
        return None
    if area == "rom" and data_offset % 8 != 0:
        return None

    return MfsDirectoryEntry(
        entry_id=entry_id,
        area=area,
        attr=attr,
        parent_id=parent_id,
        company_code=company_code,
        game_code=game_code,
        start_lba=start_lba,
        file_size=file_size,
        name=name,
        file_type=file_type,
        data_offset=data_offset,
        entry_offset=entry_offset,
    )


def parse_mfs_directory(
    data: bytes,
    volume: MfsVolume,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> List[MfsDirectoryEntry]:
    management = read_lba_span(
        data,
        volume.management_start_lba,
        volume.management_lba_count,
        sector_size,
    )
    directory_offset = volume.directory_offset
    directory_size = (
        len(management) - directory_offset
        if volume.directory_size < 0
        else volume.directory_size
    )
    directory = management[directory_offset : directory_offset + directory_size]

    entries: List[MfsDirectoryEntry] = []
    for index in range(0, len(directory) - MFS_DIR_ENTRY_SIZE + 1, MFS_DIR_ENTRY_SIZE):
        raw = directory[index : index + MFS_DIR_ENTRY_SIZE]
        entry = parse_mfs_directory_entry(
            raw,
            entry_id=len(entries) + 1,
            area=volume.area,
            entry_offset=directory_offset + index,
        )
        if entry is not None:
            entries.append(entry)
    return entries


def find_mfs_entries(data: bytes, sector_size: int = SECTOR_SIZE_DEFAULT) -> List[MfsDirectoryEntry]:
    entries: List[MfsDirectoryEntry] = []
    seen_ranges = set()
    for volume in find_mfs_volumes(data, sector_size):
        for entry in parse_mfs_directory(data, volume, sector_size):
            key = (entry.area, entry.start_lba, entry.data_offset, entry.file_size, entry.name)
            if key in seen_ranges:
                continue
            seen_ranges.add(key)
            entry.entry_id = len(entries) + 1
            entries.append(entry)
    return entries


def extract_files(
    image_path: str,
    manifest: Dict[str, Any],
    output_dir: str,
    overwrite: bool = False,
) -> List[Dict[str, Any]]:
    sector_size = int(manifest.get("sector_size", SECTOR_SIZE_DEFAULT))
    files = manifest["files"]
    id_width = max(2, len(str(max((int(entry["file_id"]) for entry in files), default=0))))
    image_size = os.path.getsize(image_path)
    results: List[Dict[str, Any]] = []

    os.makedirs(output_dir, exist_ok=True)
    with open(image_path, "rb") as image:
        for entry in files:
            lba_start = int(entry["lba_start"])
            lba_length = int(entry["lba_length"])
            if lba_start < 0 or lba_length <= 0:
                raise ValueError(f"Invalid LBA range for file_id {entry.get('file_id')}")

            offset = lba_data_offset(image_size, lba_start, 0, sector_size)
            if image_size == NDD_IMAGE_SIZE:
                if lba_start + lba_length > len(NDD_LBA_MAP):
                    raise ValueError(
                        f"file_id {entry.get('file_id')} exceeds LBA map: "
                        f"lba {lba_start}+{lba_length}"
                    )
                size = sum(NDD_LBA_MAP[lba_start + index].size for index in range(lba_length))
            else:
                size = lba_length * sector_size
            if "file_size" in entry and entry["file_size"] not in (None, ""):
                size = int(entry["file_size"])
            if offset + size > image_size:
                raise ValueError(
                    f"file_id {entry.get('file_id')} exceeds image size: "
                    f"offset 0x{offset:X}, size 0x{size:X}"
                )

            out_path = os.path.join(output_dir, output_filename(entry, id_width))
            if os.path.exists(out_path) and not overwrite:
                raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")

            image.seek(offset)
            data = image.read(size)
            with open(out_path, "wb") as out_file:
                out_file.write(data)

            results.append(
                {
                    "file_id": int(entry["file_id"]),
                    "file_name": entry.get("file_name", ""),
                    "output": out_path,
                    "offset": offset,
                    "size": size,
                    "load_address": entry.get("load_address"),
                    "entry_point": entry.get("entry_point"),
                }
            )

    return results


def extract_mfs_files(
    image_path: str,
    output_dir: str,
    overwrite: bool = False,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> List[Dict[str, Any]]:
    with open(image_path, "rb") as image:
        data = image.read()

    entries = find_mfs_entries(data, sector_size)
    if not entries:
        raise ValueError("No MFS directory entries found")

    os.makedirs(output_dir, exist_ok=True)
    id_width = max(2, len(str(len(entries))))
    results: List[Dict[str, Any]] = []
    for entry in entries:
        offset = lba_data_offset(len(data), entry.start_lba, entry.data_offset, sector_size)
        if offset + entry.file_size > len(data):
            raise ValueError(
                f"MFS entry {entry.name} exceeds image size: "
                f"offset 0x{offset:X}, size 0x{entry.file_size:X}"
            )

        out_path = os.path.join(output_dir, output_mfs_filename(entry, id_width))
        if os.path.exists(out_path) and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")

        with open(out_path, "wb") as out_file:
            out_file.write(data[offset : offset + entry.file_size])

        results.append(
            {
                "file_id": entry.entry_id,
                "file_name": entry.full_name,
                "output": out_path,
                "offset": offset,
                "size": entry.file_size,
                "lba_start": entry.start_lba,
                "block_offset": entry.data_offset,
                "area": entry.area,
                "attr": f"0x{entry.attr:04X}",
            }
        )

    return results


def build_manifest_from_mfs(
    image_path: str,
    sector_size: int = SECTOR_SIZE_DEFAULT,
) -> Dict[str, Any]:
    with open(image_path, "rb") as image:
        data = image.read()

    entries = find_mfs_entries(data, sector_size)
    return {
        "source_file": os.path.basename(image_path),
        "sector_size": sector_size,
        "lba_map": "ndd-variable" if len(data) == NDD_IMAGE_SIZE else "fixed",
        "file_count": len(entries),
        "files": [
            {
                "file_id": entry.entry_id,
                "file_name": entry.full_name,
                "area": entry.area,
                "lba_start": entry.start_lba,
                "block_offset": entry.data_offset,
                "file_size": entry.file_size,
                "attr": f"0x{entry.attr:04X}",
                "company_code": entry.company_code,
                "game_code": entry.game_code,
            }
            for entry in entries
        ],
    }


def print_results(results: Sequence[Dict[str, Any]], output_dir: str, verbose: bool) -> None:
    print(f"Extracted {len(results)} file(s) to {output_dir}")
    if verbose:
        for result in results:
            extra = ""
            if "lba_start" in result:
                extra = f" lba={result['lba_start']}+0x{result.get('block_offset', 0):X}"
            print(
                f"  {result['file_id']:02d} {os.path.basename(result['output'])} "
                f"offset=0x{result['offset']:X} size=0x{result['size']:X}{extra}"
            )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract files from a 64DD .ndd image using MFS metadata or a leosplit manifest."
    )
    parser.add_argument("input", help="Path to the .ndd image")
    parser.add_argument(
        "manifest",
        nargs="?",
        help="Optional JSON/YAML manifest. If omitted, extract files from MFS directory entries.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="extracted",
        help="Directory for extracted files (default: extracted)",
    )
    parser.add_argument(
        "--sector-size",
        type=int,
        default=SECTOR_SIZE_DEFAULT,
        help="Fixed sector size for non-standard test images (default: 2048)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print detected MFS entries as JSON without extracting",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing extracted files",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every extracted file with offsets and sizes",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 2
    if args.manifest and not os.path.isfile(args.manifest):
        print(f"Error: manifest file not found: {args.manifest}", file=sys.stderr)
        return 2

    try:
        if args.list:
            print(json.dumps(build_manifest_from_mfs(args.input, args.sector_size), indent=2))
            return 0
        if args.manifest:
            manifest = load_manifest(args.manifest)
            results = extract_files(args.input, manifest, args.output_dir, args.overwrite)
        else:
            results = extract_mfs_files(
                args.input,
                args.output_dir,
                args.overwrite,
                args.sector_size,
            )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, struct.error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_results(results, args.output_dir, args.verbose)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
