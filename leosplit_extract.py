#!/usr/bin/env python3
"""Extract 64DD .ndd file ranges from a leosplit manifest."""

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from leosplit_manifest import sanitize_name


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
    current_file: Dict[str, Any] | None = None

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


def extract_files(
    image_path: str,
    manifest: Dict[str, Any],
    output_dir: str,
    overwrite: bool = False,
) -> List[Dict[str, Any]]:
    sector_size = int(manifest.get("sector_size", 2048))
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

            offset = lba_start * sector_size
            size = lba_length * sector_size
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract standalone binaries from a 64DD .ndd image using a leosplit manifest."
    )
    parser.add_argument("input", help="Path to the .ndd image")
    parser.add_argument("manifest", help="Path to the JSON/YAML manifest")
    parser.add_argument(
        "-o",
        "--output-dir",
        default="extracted",
        help="Directory for extracted .bin files (default: extracted)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing extracted files",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every extracted file with offsets and load addresses",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 2
    if not os.path.isfile(args.manifest):
        print(f"Error: manifest file not found: {args.manifest}", file=sys.stderr)
        return 2

    try:
        manifest = load_manifest(args.manifest)
        results = extract_files(args.input, manifest, args.output_dir, args.overwrite)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Extracted {len(results)} file(s) to {args.output_dir}")
    if args.verbose:
        for result in results:
            print(
                f"  {result['file_id']:02d} {os.path.basename(result['output'])} "
                f"offset=0x{result['offset']:X} size=0x{result['size']:X} "
                f"load={result['load_address']} entry={result['entry_point']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
