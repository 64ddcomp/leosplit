import json
import os
import struct
import tempfile
import unittest

from leosplit.disassembler.leosplit_asm import (
    create_workspace,
    decode_instruction,
    disassemble_segment,
    infer_project_metadata,
    load_manifest,
    load_segments,
    parse_code_range_overrides,
    SplitSegment,
)


class TestLeoSplitAsm(unittest.TestCase):
    def test_decode_branch_and_jump_targets(self):
        branch = decode_instruction(0x11000003, 0x80200000)
        self.assertEqual(branch.text, "beq $t0, $zero, L80200010")
        self.assertEqual(branch.label_target, 0x80200010)

        jump = decode_instruction(0x0C080010, 0x80200000)
        self.assertEqual(jump.text, "jal L80200040")
        self.assertEqual(jump.label_target, 0x80200040)

    def test_disassemble_segment_marks_entry_and_labels(self):
        data = b"".join(
            struct.pack(">I", word)
            for word in (
                0x3C088000,  # lui $t0, 0x8000
                0x11000001,  # beq $t0, $zero, +1
                0x00000000,  # nop
                0x03E00008,  # jr $ra
                0x00000000,  # nop
            )
        )
        segment = SplitSegment(
            file_id=1,
            name="BOOT",
            safe_name="01_BOOT",
            data=data,
            rom_offset=0x100,
            size=len(data),
            vram=0x80200000,
            entry_point=0x80200000,
            lba_start=1,
            lba_length=1,
            code_ranges=[],
        )

        asm, labels, hints = disassemble_segment(segment)

        self.assertIn("L80200000:", asm)
        self.assertIn("L8020000C:", asm)
        self.assertIn("beq $t0, $zero, L8020000C", asm)
        self.assertIn("jr $ra", asm)
        self.assertEqual(labels, [0x80200000, 0x8020000C])
        self.assertEqual(hints, [])

    def test_disassemble_segment_respects_code_ranges(self):
        data = b"".join(
            struct.pack(">I", word)
            for word in (
                0xDEADBEEF,
                0x3C088000,
                0x03E00008,
                0x00000000,
            )
        )
        segment = SplitSegment(
            file_id=1,
            name="BOOT",
            safe_name="01_BOOT",
            data=data,
            rom_offset=0,
            size=len(data),
            vram=0x80200000,
            entry_point=0x80200004,
            lba_start=0,
            lba_length=1,
            code_ranges=[(0x80200004, 0x80200010)],
        )

        asm, labels, _ = disassemble_segment(segment)

        self.assertNotIn("DEADBEEF", asm)
        self.assertIn("lui $t0, 0x8000", asm)
        self.assertIn("Explicit code ranges", asm)
        self.assertEqual(labels, [0x80200004])

    def test_create_workspace(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "test.ndd")
            manifest_path = os.path.join(tmp_dir, "manifest.json")
            output_dir = os.path.join(tmp_dir, "split")
            words = (0x3C088000, 0x25080010, 0x03E00008, 0x00000000)
            payload = b"".join(struct.pack(">I", word) for word in words)
            with open(image_path, "wb") as f:
                f.write(b"\x00" * 4)
                f.write(payload)

            manifest = {
                "source_file": "test.ndd",
                "sector_size": 4,
                "file_count": 1,
                "files": [
                    {
                        "file_id": 1,
                        "file_name": "BOOT",
                        "lba_start": 1,
                        "lba_length": 4,
                        "load_address": "0x80200000",
                        "entry_point": "0x80200000",
                    }
                ],
            }
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            results = create_workspace(image_path, manifest_path, output_dir)

            self.assertEqual(len(results), 1)
            self.assertTrue(os.path.isfile(os.path.join(output_dir, "leosplit.yaml")))
            self.assertTrue(os.path.isfile(os.path.join(output_dir, "macro.inc")))
            self.assertTrue(os.path.isfile(os.path.join(output_dir, "test.ld")))
            self.assertTrue(os.path.isfile(os.path.join(output_dir, "Makefile")))
            self.assertTrue(os.path.isfile(os.path.join(output_dir, "leosplit_workspace.json")))
            with open(os.path.join(output_dir, "asm", "01_BOOT.s"), "r", encoding="utf-8") as f:
                asm = f.read()
            self.assertIn("vram=0x80200000", asm)
            self.assertIn("addiu $t0, $t0, 0x10", asm)
            with open(os.path.join(output_dir, "macro.inc"), "r", encoding="utf-8") as f:
                self.assertIn(".macro glabel name", f.read())
            with open(os.path.join(output_dir, "test.ld"), "r", encoding="utf-8") as f:
                ld_text = f.read()
            self.assertIn("OUTPUT_ARCH(mips)", ld_text)
            self.assertIn(".seg_01_BOOT", ld_text)
            with open(os.path.join(output_dir, "Makefile"), "r", encoding="utf-8") as f:
                makefile = f.read()
            self.assertIn("$(PYTHON) -m leosplit.builder.leosplit_build", makefile)
            self.assertIn("SOURCE_IMAGE := ../test.ndd", makefile)
            with open(os.path.join(output_dir, "bin", "01_BOOT.bin"), "rb") as f:
                self.assertEqual(f.read(), payload)
            with open(os.path.join(output_dir, "symbols", "01_BOOT.sym"), "r", encoding="utf-8") as f:
                self.assertIn("L80200000 = 0x80200000; // entry", f.read())
            with open(os.path.join(output_dir, "leosplit.yaml"), "r", encoding="utf-8") as f:
                yaml_text = f.read()
            self.assertIn("name: test", yaml_text)
            self.assertIn("basename: test", yaml_text)
            self.assertIn("ld_script_path: test.ld", yaml_text)
            self.assertIn("compiler_detection:", yaml_text)

    def test_load_segments_uses_manifest_addresses(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "test.ndd")
            manifest_path = os.path.join(tmp_dir, "manifest.json")
            with open(image_path, "wb") as f:
                f.write(bytes(range(32)))
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "source_file": "test.ndd",
                        "sector_size": 4,
                        "file_count": 1,
                        "files": [
                            {
                                "file_id": 7,
                                "file_name": "NI/CHI",
                                "lba_start": 2,
                                "lba_length": 2,
                                "load_address": "0x80300000",
                                "entry_point": "0x80300010",
                            }
                        ],
                    },
                    f,
                )

            segments = load_segments(image_path, load_manifest(manifest_path))

        self.assertEqual(segments[0].safe_name, "07_NI_CHI")
        self.assertEqual(segments[0].vram, 0x80300000)
        self.assertEqual(segments[0].entry_point, 0x80300010)
        self.assertEqual(segments[0].data, bytes(range(8, 16)))

    def test_parse_code_range_overrides(self):
        overrides = parse_code_range_overrides(["1:0x80200000-0x80200100"])
        self.assertEqual(overrides, {"1": [(0x80200000, 0x80200100)]})

    def test_infer_project_metadata_from_known_disk_code(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "NUD-DSCJ-JPN.ndd")
            with open(image_path, "wb") as f:
                f.write(b"\x00" * 128)

            metadata = infer_project_metadata(
                image_path,
                {"source_file": "NUD-DSCJ-JPN.ndd"},
            )

        self.assertEqual(metadata.name, "Sim City 64")
        self.assertEqual(metadata.basename, "simcity64")
        self.assertEqual(metadata.ld_script_path, "simcity64.ld")
        self.assertEqual(metadata.game_code, "DSCJ")

    def test_infer_project_metadata_honors_overrides(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "NUD-DMTJ-JPN1.ndd")
            with open(image_path, "wb") as f:
                f.write(b"\x00" * 128)

            metadata = infer_project_metadata(
                image_path,
                {"source_file": "NUD-DMTJ-JPN1.ndd"},
                name_override="My Game",
                basename_override="mygame",
                compiler_override="GCC",
                ld_script_override="custom.ld",
            )

        self.assertEqual(metadata.name, "My Game")
        self.assertEqual(metadata.basename, "mygame")
        self.assertEqual(metadata.compiler, "GCC")
        self.assertEqual(metadata.compiler_detection, "provided by --compiler")
        self.assertEqual(metadata.ld_script_path, "custom.ld")


if __name__ == "__main__":
    unittest.main()
