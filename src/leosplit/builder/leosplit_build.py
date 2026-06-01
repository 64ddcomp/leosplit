#!/usr/bin/env python3
"""Rebuild a disk image from a leosplit workspace."""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

WORKSPACE_MANIFEST = "leosplit_workspace.json"


def load_workspace_manifest(workspace_dir: str) -> Dict[str, Any]:
    path = os.path.join(workspace_dir, WORKSPACE_MANIFEST)
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("segments"), list):
        raise ValueError(f"{WORKSPACE_MANIFEST} must contain a segments list")
    return manifest


def read_base_image(
    workspace_dir: str,
    manifest: Dict[str, Any],
    base_image: Optional[str],
) -> bytearray:
    if base_image:
        with open(base_image, "rb") as f:
            return bytearray(f.read())

    source_file = str(manifest.get("source_file") or "")
    source_path = os.path.join(workspace_dir, source_file) if source_file else ""
    if source_path and os.path.isfile(source_path):
        with open(source_path, "rb") as f:
            return bytearray(f.read())

    image_size = int(manifest.get("image_size") or 0)
    if image_size <= 0:
        raise ValueError("A base image path or positive image_size is required")
    return bytearray(image_size)


def patch_segment(
    image: bytearray,
    workspace_dir: str,
    segment: Dict[str, Any],
    allow_size_mismatch: bool = False,
) -> Dict[str, Any]:
    path = os.path.join(workspace_dir, str(segment["bin_path"]))
    offset = int(segment["rom_offset"])
    expected_size = int(segment["size"])
    with open(path, "rb") as f:
        data = f.read()

    if len(data) != expected_size and not allow_size_mismatch:
        raise ValueError(
            f"{segment.get('name', path)} size mismatch: "
            f"got 0x{len(data):X}, expected 0x{expected_size:X}"
        )
    if offset < 0 or offset + len(data) > len(image):
        raise ValueError(
            f"{segment.get('name', path)} exceeds output image: "
            f"offset 0x{offset:X}, size 0x{len(data):X}"
        )

    image[offset : offset + len(data)] = data
    return {
        "name": segment.get("name", os.path.basename(path)),
        "offset": offset,
        "size": len(data),
        "path": path,
    }


def sha1_file(path: str) -> str:
    digest = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rebuild_image(
    workspace_dir: str,
    output_path: str,
    base_image: Optional[str] = None,
    allow_size_mismatch: bool = False,
) -> List[Dict[str, Any]]:
    manifest = load_workspace_manifest(workspace_dir)
    image = read_base_image(workspace_dir, manifest, base_image)
    patched = [
        patch_segment(image, workspace_dir, segment, allow_size_mismatch)
        for segment in manifest["segments"]
    ]

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as out_file:
        out_file.write(image)
    return patched


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild a 64DD image from a leosplit workspace."
    )
    parser.add_argument("workspace", help="Path to a leosplit workspace directory")
    parser.add_argument("-o", "--output", required=True, help="Output rebuilt image path")
    parser.add_argument("--base", help="Original/base image to patch")
    parser.add_argument(
        "--compare",
        help="Compare rebuilt output SHA-1 against this image after writing",
    )
    parser.add_argument(
        "--allow-size-mismatch",
        action="store_true",
        help="Allow replacement bins that differ from the original segment size",
    )
    parser.add_argument("--verbose", action="store_true", help="Print patched segments")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if not os.path.isdir(args.workspace):
        print(f"Error: workspace not found: {args.workspace}", file=sys.stderr)
        return 2

    try:
        patched = rebuild_image(
            args.workspace,
            args.output,
            args.base,
            args.allow_size_mismatch,
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Rebuilt {args.output} from {len(patched)} segment(s)")
    if args.verbose:
        for segment in patched:
            print(
                f"  {segment['name']} offset=0x{segment['offset']:X} "
                f"size=0x{segment['size']:X}"
            )

    if args.compare:
        output_hash = sha1_file(args.output)
        compare_hash = sha1_file(args.compare)
        if output_hash != compare_hash:
            print(
                f"Compare failed: {output_hash} != {compare_hash}",
                file=sys.stderr,
            )
            return 1
        print(f"Compare OK: {output_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
