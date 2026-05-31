#!/usr/bin/env python3
"""Create Splat-like assembly workspaces from leosplit manifests."""

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from leosplit.extractor.leosplit_extract import (
    NDD_IMAGE_SIZE,
    NDD_LBA_MAP,
    lba_data_offset,
    load_manifest,
)
from leosplit.manifestor.leosplit_manifest import sanitize_name


@dataclass
class SplitSegment:
    file_id: int
    name: str
    safe_name: str
    data: bytes
    rom_offset: int
    size: int
    vram: int
    entry_point: int
    lba_start: int
    lba_length: int
    code_ranges: List[Tuple[int, int]]


@dataclass(frozen=True)
class DecodedInstruction:
    address: int
    word: int
    text: str
    label_target: Optional[int] = None
    is_return: bool = False


@dataclass(frozen=True)
class ProjectMetadata:
    name: str
    basename: str
    compiler: str
    ld_script_path: str
    game_code: str
    compiler_detection: str


KNOWN_DISK_TITLES = {
    "DMTJ": "Mario Artist Talent Studio",
    "DSCJ": "Sim City 64",
}


KNOWN_DISK_BASENAMES = {
    "DMTJ": "talentstudio",
    "DSCJ": "simcity64",
}


REGISTER_NAMES = (
    "zero",
    "at",
    "v0",
    "v1",
    "a0",
    "a1",
    "a2",
    "a3",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "t7",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "t8",
    "t9",
    "k0",
    "k1",
    "gp",
    "sp",
    "fp",
    "ra",
)

SPECIAL_OPS = {
    0x08: "jr",
    0x09: "jalr",
    0x20: "add",
    0x21: "addu",
    0x22: "sub",
    0x23: "subu",
    0x24: "and",
    0x25: "or",
    0x26: "xor",
    0x27: "nor",
    0x2A: "slt",
    0x2B: "sltu",
}

IMM_OPS = {
    0x08: "addi",
    0x09: "addiu",
    0x0A: "slti",
    0x0B: "sltiu",
    0x0C: "andi",
    0x0D: "ori",
    0x0E: "xori",
    0x20: "lb",
    0x21: "lh",
    0x23: "lw",
    0x24: "lbu",
    0x25: "lhu",
    0x28: "sb",
    0x29: "sh",
    0x2B: "sw",
    0x31: "lwc1",
    0x39: "swc1",
}

REGIMM_OPS = {
    0x00: "bltz",
    0x01: "bgez",
    0x10: "bltzal",
    0x11: "bgezal",
}

COP0_NAMES = {
    0x00: "mfc0",
    0x04: "mtc0",
}


def parse_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def format_hex(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}X}"


def reg(index: int) -> str:
    return f"${REGISTER_NAMES[index]}"


def sign_extend_16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def format_imm(value: int) -> str:
    return f"-0x{-value:X}" if value < 0 else f"0x{value:X}"


def format_offset(base: int, offset: int) -> str:
    return f"{format_imm(offset)}({reg(base)})"


def label_for(address: int) -> str:
    return f"L{address:08X}"


def slugify_name(name: str) -> str:
    slug = sanitize_name(name).lower()
    return slug.replace(".", "_") or "unknown"


def yaml_scalar(value: str) -> str:
    if value == "" or any(ch in value for ch in ":#[]{}&,*?|\"><!%@`"):
        return json.dumps(value)
    return value


def extract_disk_code(path: str) -> str:
    stem = os.path.splitext(os.path.basename(path))[0].upper()
    parts = stem.split("-")
    if len(parts) >= 2 and len(parts[1]) >= 4:
        return parts[1][:4]
    return ""


def decode_ascii_title(data: bytes, offset: int, size: int = 64) -> str:
    raw = data[offset : offset + size].split(b"\x00", 1)[0].strip()
    if len(raw) < 4:
        return ""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return ""
    if sum(ch.isprintable() and not ch.isspace() for ch in text) < 4:
        return ""
    return " ".join(text.split())


def find_embedded_title(data: bytes) -> str:
    title_patterns = [
        b"SimCity 64",
        b"SimCity",
        b"Mario Artist Talent Studio",
        b"MarioArtist",
    ]
    for pattern in title_patterns:
        if pattern in data:
            return pattern.decode("ascii")
    return decode_ascii_title(data, 0x20)


def detect_compiler(data: bytes) -> Tuple[str, str]:
    markers = (
        (b"SN Systems", "SN64", "matched SN Systems marker"),
        (b"SN64", "SN64", "matched SN64 marker"),
        (b"egcs", "GCC", "matched egcs marker"),
        (b"GCC:", "GCC", "matched GCC version marker"),
        (b"gcc version", "GCC", "matched GCC version marker"),
        (b"CodeWarrior", "MWCC", "matched CodeWarrior marker"),
    )
    lowered = data.lower()
    for marker, compiler, reason in markers:
        haystack = lowered if marker.islower() else data
        if marker in haystack:
            return compiler, reason
    return "IDO", "assumed N64/N64DD default; no compiler marker found"


def infer_project_metadata(
    image_path: str,
    manifest: Dict[str, Any],
    name_override: Optional[str] = None,
    basename_override: Optional[str] = None,
    compiler_override: Optional[str] = None,
    ld_script_override: Optional[str] = None,
) -> ProjectMetadata:
    source_file = str(manifest.get("source_file") or os.path.basename(image_path))
    disk_code = extract_disk_code(source_file) or extract_disk_code(image_path)

    with open(image_path, "rb") as image:
        probe = image.read(4 * 1024 * 1024)

    title = (
        name_override
        or str(manifest.get("name") or "")
        or KNOWN_DISK_TITLES.get(disk_code, "")
        or find_embedded_title(probe)
        or os.path.splitext(os.path.basename(source_file))[0]
    )
    basename = (
        basename_override
        or str(manifest.get("basename") or "")
        or KNOWN_DISK_BASENAMES.get(disk_code, "")
        or slugify_name(title)
    )
    compiler, compiler_detection = detect_compiler(probe)
    if compiler_override:
        compiler = compiler_override
        compiler_detection = "provided by --compiler"

    ld_script_path = ld_script_override or str(manifest.get("ld_script_path") or f"{basename}.ld")

    return ProjectMetadata(
        name=title,
        basename=basename,
        compiler=compiler,
        ld_script_path=ld_script_path,
        game_code=disk_code,
        compiler_detection=compiler_detection,
    )


def decode_instruction(word: int, address: int) -> DecodedInstruction:
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    shamt = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = sign_extend_16(imm)
    target = word & 0x03FFFFFF

    if word == 0:
        return DecodedInstruction(address, word, "nop")

    if op == 0:
        if funct in (0x00, 0x02, 0x03):
            mnemonic = {0x00: "sll", 0x02: "srl", 0x03: "sra"}[funct]
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rd)}, {reg(rt)}, {shamt}")
        if funct in (0x04, 0x06, 0x07):
            mnemonic = {0x04: "sllv", 0x06: "srlv", 0x07: "srav"}[funct]
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rd)}, {reg(rt)}, {reg(rs)}")
        if funct == 0x08:
            return DecodedInstruction(address, word, f"jr {reg(rs)}", is_return=(rs == 31))
        if funct == 0x09:
            return DecodedInstruction(address, word, f"jalr {reg(rd)}, {reg(rs)}")
        if funct in SPECIAL_OPS:
            return DecodedInstruction(
                address,
                word,
                f"{SPECIAL_OPS[funct]} {reg(rd)}, {reg(rs)}, {reg(rt)}",
            )
        if funct in (0x10, 0x12):
            mnemonic = "mfhi" if funct == 0x10 else "mflo"
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rd)}")
        if funct in (0x11, 0x13):
            mnemonic = "mthi" if funct == 0x11 else "mtlo"
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rs)}")
        if funct in (0x18, 0x19, 0x1A, 0x1B):
            mnemonic = {0x18: "mult", 0x19: "multu", 0x1A: "div", 0x1B: "divu"}[funct]
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rs)}, {reg(rt)}")

    if op in (0x02, 0x03):
        jump_target = ((address + 4) & 0xF0000000) | (target << 2)
        mnemonic = "j" if op == 0x02 else "jal"
        return DecodedInstruction(address, word, f"{mnemonic} {label_for(jump_target)}", jump_target)

    if op in (0x04, 0x05):
        branch_target = address + 4 + (simm << 2)
        mnemonic = "beq" if op == 0x04 else "bne"
        return DecodedInstruction(
            address,
            word,
            f"{mnemonic} {reg(rs)}, {reg(rt)}, {label_for(branch_target)}",
            branch_target,
        )

    if op in (0x06, 0x07):
        branch_target = address + 4 + (simm << 2)
        mnemonic = "blez" if op == 0x06 else "bgtz"
        return DecodedInstruction(
            address,
            word,
            f"{mnemonic} {reg(rs)}, {label_for(branch_target)}",
            branch_target,
        )

    if op == 0x01 and rt in REGIMM_OPS:
        branch_target = address + 4 + (simm << 2)
        return DecodedInstruction(
            address,
            word,
            f"{REGIMM_OPS[rt]} {reg(rs)}, {label_for(branch_target)}",
            branch_target,
        )

    if op == 0x0F:
        return DecodedInstruction(address, word, f"lui {reg(rt)}, 0x{imm:X}")

    if op in IMM_OPS:
        mnemonic = IMM_OPS[op]
        if mnemonic in {"lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw", "lwc1", "swc1"}:
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rt)}, {format_offset(rs, simm)}")
        if mnemonic in {"andi", "ori", "xori"}:
            return DecodedInstruction(address, word, f"{mnemonic} {reg(rt)}, {reg(rs)}, 0x{imm:X}")
        return DecodedInstruction(address, word, f"{mnemonic} {reg(rt)}, {reg(rs)}, {format_imm(simm)}")

    if op in (0x10, 0x11, 0x12):
        cop_name = {0x10: "cop0", 0x11: "cop1", 0x12: "cop2"}[op]
        if op == 0x10 and rs in COP0_NAMES:
            return DecodedInstruction(address, word, f"{COP0_NAMES[rs]} {reg(rt)}, ${rd}")
        return DecodedInstruction(address, word, f".word 0x{word:08X} /* {cop_name} */")

    return DecodedInstruction(address, word, f".word 0x{word:08X}")


def iter_words(data: bytes, vram: int, start: int, end: int) -> Iterable[Tuple[int, int]]:
    aligned_start = max(0, start - vram)
    aligned_end = min(len(data), end - vram)
    aligned_start += (-aligned_start) % 4
    aligned_end -= aligned_end % 4
    for offset in range(aligned_start, aligned_end, 4):
        yield vram + offset, struct.unpack_from(">I", data, offset)[0]


def likely_ascii_run(data: bytes, offset: int, min_len: int = 8) -> bool:
    run = 0
    for byte in data[offset:]:
        if byte in (0x09, 0x0A, 0x0D) or 0x20 <= byte <= 0x7E:
            run += 1
            if run >= min_len:
                return True
        elif byte == 0 and run >= min_len:
            return True
        else:
            return False
    return False


def find_data_hints(data: bytes, vram: int) -> List[Tuple[int, str]]:
    hints: List[Tuple[int, str]] = []
    zero_run_start: Optional[int] = None
    zero_run_len = 0
    for offset in range(0, len(data), 4):
        word = data[offset : offset + 4]
        if word == b"\x00\x00\x00\x00":
            if zero_run_start is None:
                zero_run_start = offset
            zero_run_len += 4
        else:
            if zero_run_start is not None and zero_run_len >= 0x20:
                hints.append((vram + zero_run_start, f"zero/data run, {zero_run_len} bytes"))
            zero_run_start = None
            zero_run_len = 0

        if likely_ascii_run(data, offset):
            hints.append((vram + offset, "possible ASCII/string data"))

    if zero_run_start is not None and zero_run_len >= 0x20:
        hints.append((vram + zero_run_start, f"zero/data run, {zero_run_len} bytes"))

    deduped: List[Tuple[int, str]] = []
    seen = set()
    for address, reason in hints:
        if address in seen:
            continue
        seen.add(address)
        deduped.append((address, reason))
    return deduped


def normalized_code_ranges(segment: SplitSegment) -> List[Tuple[int, int]]:
    segment_start = segment.vram
    segment_end = segment.vram + len(segment.data)
    if not segment.code_ranges:
        return [(segment_start, segment_end)]

    ranges = []
    for start, end in segment.code_ranges:
        if end <= start:
            raise ValueError(f"Invalid code range for {segment.safe_name}: {format_hex(start)}-{format_hex(end)}")
        clipped_start = max(segment_start, start)
        clipped_end = min(segment_end, end)
        if clipped_start >= clipped_end:
            raise ValueError(
                f"Code range is outside {segment.safe_name}: "
                f"{format_hex(start)}-{format_hex(end)}"
            )
        ranges.append((clipped_start, clipped_end))
    return sorted(ranges)


def disassemble_segment(segment: SplitSegment) -> Tuple[str, List[int], List[Tuple[int, str]]]:
    code_ranges = normalized_code_ranges(segment)
    decoded = [
        decode_instruction(word, address)
        for start, end in code_ranges
        for address, word in iter_words(segment.data, segment.vram, start, end)
    ]
    labels: Set[int] = {segment.entry_point}
    labels.update(inst.label_target for inst in decoded if inst.label_target is not None)
    labels = {address for address in labels if segment.vram <= address < segment.vram + len(segment.data)}
    data_hints = find_data_hints(segment.data, segment.vram)

    lines = [
        ".include \"macro.inc\"",
        "",
        ".set noat",
        ".set noreorder",
        ".set gp=64",
        "",
        ".section .text",
        "",
        f"/* {segment.name}: rom={format_hex(segment.rom_offset)} "
        f"vram={format_hex(segment.vram)} size={format_hex(segment.size)} "
        f"entry={format_hex(segment.entry_point)} */",
    ]
    if segment.code_ranges:
        lines.append("/* Explicit code ranges:")
        for start, end in code_ranges:
            lines.append(f" *   {format_hex(start)}-{format_hex(end)}")
        lines.append(" */")

    if data_hints:
        lines.append("/*")
        lines.append(" * Data boundary hints:")
        for address, reason in data_hints[:64]:
            lines.append(f" *   {format_hex(address)}: {reason}")
        if len(data_hints) > 64:
            lines.append(f" *   ... {len(data_hints) - 64} more")
        lines.append(" */")

    for inst in decoded:
        if inst.address in labels:
            lines.append("")
            lines.append(f"{label_for(inst.address)}:")
        comment = " /* entry */" if inst.address == segment.entry_point else ""
        lines.append(f"/* {inst.address:08X} {inst.word:08X} */  {inst.text}{comment}")

    remainder = len(segment.data) % 4
    if remainder:
        tail = segment.data[-remainder:]
        values = ", ".join(f"0x{byte:02X}" for byte in tail)
        lines.append(f".byte {values}")

    lines.append("")
    return "\n".join(lines), sorted(labels), data_hints


def read_segment_data(image_data: bytes, entry: Dict[str, Any], sector_size: int) -> Tuple[bytes, int, int]:
    lba_start = parse_int(entry["lba_start"])
    lba_length = parse_int(entry["lba_length"])
    rom_offset = lba_data_offset(len(image_data), lba_start, 0, sector_size)
    if len(image_data) == NDD_IMAGE_SIZE:
        if lba_start + lba_length > len(NDD_LBA_MAP):
            raise ValueError(f"LBA range exceeds .ndd image: {lba_start}+{lba_length}")
        size = sum(NDD_LBA_MAP[lba_start + index].size for index in range(lba_length))
    else:
        size = lba_length * sector_size
    if "file_size" in entry and entry["file_size"] not in (None, ""):
        size = parse_int(entry["file_size"])
    return image_data[rom_offset : rom_offset + size], rom_offset, size


def load_entry_code_ranges(entry: Dict[str, Any]) -> List[Tuple[int, int]]:
    ranges = []
    for item in entry.get("code_ranges", []) or []:
        if isinstance(item, dict):
            ranges.append((parse_int(item["start"]), parse_int(item["end"])))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            ranges.append((parse_int(item[0]), parse_int(item[1])))
        else:
            raise ValueError(f"Invalid code range in manifest entry {entry.get('file_id')}: {item}")
    return ranges


def apply_code_range_overrides(
    segments: Sequence[SplitSegment],
    overrides: Dict[str, List[Tuple[int, int]]],
) -> None:
    for segment in segments:
        keys = {str(segment.file_id), segment.name, segment.safe_name}
        matched = []
        for key in keys:
            matched.extend(overrides.get(key, []))
        if matched:
            segment.code_ranges = matched


def load_segments(
    image_path: str,
    manifest: Dict[str, Any],
    code_range_overrides: Optional[Dict[str, List[Tuple[int, int]]]] = None,
) -> List[SplitSegment]:
    sector_size = parse_int(manifest.get("sector_size"), 2048)
    with open(image_path, "rb") as image:
        image_data = image.read()

    segments: List[SplitSegment] = []
    for entry in manifest["files"]:
        file_id = parse_int(entry["file_id"])
        name = str(entry.get("file_name") or f"file_{file_id:02d}")
        data, rom_offset, size = read_segment_data(image_data, entry, sector_size)
        vram = parse_int(entry.get("load_address"))
        entry_point = parse_int(entry.get("entry_point"), vram)
        safe_name = f"{file_id:02d}_{sanitize_name(name)}"
        segments.append(
            SplitSegment(
                file_id=file_id,
                name=name,
                safe_name=safe_name,
                data=data,
                rom_offset=rom_offset,
                size=size,
                vram=vram,
                entry_point=entry_point,
                lba_start=parse_int(entry["lba_start"]),
                lba_length=parse_int(entry["lba_length"]),
                code_ranges=load_entry_code_ranges(entry),
            )
        )
    if code_range_overrides:
        apply_code_range_overrides(segments, code_range_overrides)
    return segments


def dump_workspace_yaml(
    image_path: str,
    manifest: Dict[str, Any],
    segments: Sequence[SplitSegment],
    metadata: ProjectMetadata,
) -> str:
    lines = [
        f"name: {yaml_scalar(metadata.name)}",
        f"basename: {yaml_scalar(metadata.basename)}",
        "platform: n64dd",
        f"source_file: {os.path.basename(image_path)}",
        f"game_code: {yaml_scalar(metadata.game_code)}",
        "options:",
        f"  compiler: {yaml_scalar(metadata.compiler)}",
        f"  compiler_detection: {yaml_scalar(metadata.compiler_detection)}",
        "  asm_path: asm",
        "  src_path: src",
        "  build_path: build",
        f"  ld_script_path: {yaml_scalar(metadata.ld_script_path)}",
        "segments:",
    ]
    for segment in segments:
        lines.extend(
            [
                f"  - name: {segment.safe_name}",
                "    type: asm",
                f"    start: {format_hex(segment.rom_offset)}",
                f"    vram: {format_hex(segment.vram)}",
                f"    entry: {format_hex(segment.entry_point)}",
                f"    size: {format_hex(segment.size)}",
                f"    lba: {segment.lba_start}",
                f"    path: asm/{segment.safe_name}.s",
            ]
        )
        if segment.code_ranges:
            lines.append("    code_ranges:")
            for start, end in segment.code_ranges:
                lines.extend(
                    [
                        f"      - start: {format_hex(start)}",
                        f"        end: {format_hex(end)}",
                    ]
                )
    return "\n".join(lines) + "\n"


def dump_symbols(segment: SplitSegment, labels: Sequence[int], data_hints: Sequence[Tuple[int, str]]) -> str:
    lines = [
        f"// Symbols and hints for {segment.name}",
        f"segment_{segment.safe_name}_VRAM = {format_hex(segment.vram)};",
        f"segment_{segment.safe_name}_ENTRY = {format_hex(segment.entry_point)};",
        "",
    ]
    for address in labels:
        kind = "entry" if address == segment.entry_point else "local_label"
        lines.append(f"{label_for(address)} = {format_hex(address)}; // {kind}")
    if data_hints:
        lines.append("")
        lines.append("// Data boundary hints")
        for address, reason in data_hints:
            lines.append(f"{label_for(address)} = {format_hex(address)}; // {reason}")
    return "\n".join(lines) + "\n"


def write_bytes(path: str, data: bytes, overwrite: bool) -> None:
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    with open(path, "wb") as out_file:
        out_file.write(data)


def write_text(path: str, text: str, overwrite: bool) -> None:
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing file: {path}")
    with open(path, "w", encoding="utf-8", newline="\n") as out_file:
        out_file.write(text)


def create_workspace(
    image_path: str,
    manifest_path: str,
    output_dir: str,
    overwrite: bool = False,
    code_range_overrides: Optional[Dict[str, List[Tuple[int, int]]]] = None,
    name_override: Optional[str] = None,
    basename_override: Optional[str] = None,
    compiler_override: Optional[str] = None,
    ld_script_override: Optional[str] = None,
) -> List[Dict[str, Any]]:
    manifest = load_manifest(manifest_path)
    segments = load_segments(image_path, manifest, code_range_overrides)
    metadata = infer_project_metadata(
        image_path,
        manifest,
        name_override,
        basename_override,
        compiler_override,
        ld_script_override,
    )

    asm_dir = os.path.join(output_dir, "asm")
    bin_dir = os.path.join(output_dir, "bin")
    symbol_dir = os.path.join(output_dir, "symbols")
    os.makedirs(asm_dir, exist_ok=True)
    os.makedirs(bin_dir, exist_ok=True)
    os.makedirs(symbol_dir, exist_ok=True)

    results: List[Dict[str, Any]] = []
    for segment in segments:
        asm_text, labels, data_hints = disassemble_segment(segment)
        asm_path = os.path.join(asm_dir, f"{segment.safe_name}.s")
        bin_path = os.path.join(bin_dir, f"{segment.safe_name}.bin")
        symbol_path = os.path.join(symbol_dir, f"{segment.safe_name}.sym")
        write_text(asm_path, asm_text, overwrite)
        write_bytes(bin_path, segment.data, overwrite)
        write_text(symbol_path, dump_symbols(segment, labels, data_hints), overwrite)
        results.append(
            {
                "name": segment.safe_name,
                "asm": asm_path,
                "bin": bin_path,
                "symbols": symbol_path,
                "vram": segment.vram,
                "entry": segment.entry_point,
                "labels": len(labels),
                "data_hints": len(data_hints),
            }
        )

    write_text(
        os.path.join(output_dir, "leosplit.yaml"),
        dump_workspace_yaml(image_path, manifest, segments, metadata),
        overwrite,
    )
    return results


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a Splat-like assembly workspace from a 64DD .ndd image and leosplit manifest."
    )
    parser.add_argument("input", help="Path to the .ndd image")
    parser.add_argument("manifest", help="Path to the JSON/YAML manifest")
    parser.add_argument("--name", help="Project/game display name for leosplit.yaml")
    parser.add_argument("--basename", help="Project basename for paths and linker script defaults")
    parser.add_argument("--compiler", help="Override inferred compiler")
    parser.add_argument("--ld-script-path", help="Override linker script path in leosplit.yaml")
    parser.add_argument(
        "-o",
        "--output-dir",
        default="split",
        help="Directory for asm/bin/symbol output (default: split)",
    )
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing files")
    parser.add_argument(
        "--code-range",
        action="append",
        default=[],
        metavar="SEGMENT:START-END",
        help=(
            "Restrict disassembly to a VRAM range for one segment. SEGMENT can be file_id, "
            "file_name, or generated safe name. Can be used multiple times."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Print each generated segment")
    return parser.parse_args()


def parse_code_range_overrides(values: Sequence[str]) -> Dict[str, List[Tuple[int, int]]]:
    overrides: Dict[str, List[Tuple[int, int]]] = {}
    for value in values:
        if ":" not in value or "-" not in value:
            raise ValueError(f"Invalid --code-range value: {value}")
        segment_key, range_text = value.split(":", 1)
        start_text, end_text = range_text.split("-", 1)
        segment_key = segment_key.strip()
        if not segment_key:
            raise ValueError(f"Invalid --code-range segment key: {value}")
        overrides.setdefault(segment_key, []).append((int(start_text, 0), int(end_text, 0)))
    return overrides


def main() -> int:
    args = parse_arguments()
    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return 2
    if not os.path.isfile(args.manifest):
        print(f"Error: manifest file not found: {args.manifest}", file=sys.stderr)
        return 2

    try:
        results = create_workspace(
            args.input,
            args.manifest,
            args.output_dir,
            args.overwrite,
            parse_code_range_overrides(args.code_range),
            args.name,
            args.basename,
            args.compiler,
            args.ld_script_path,
        )
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, struct.error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote {len(results)} segment(s) to {args.output_dir}")
    if args.verbose:
        for result in results:
            print(
                f"  {result['name']} vram={format_hex(result['vram'])} "
                f"entry={format_hex(result['entry'])} labels={result['labels']} "
                f"data_hints={result['data_hints']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
