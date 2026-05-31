import json
import os
import struct
import tempfile
import unittest

from leosplit.extractor.leosplit_extract import (
    NDD_IMAGE_SIZE,
    NDD_LBA_MAP,
    build_manifest_from_mfs,
    extract_files,
    extract_mfs_files,
    find_mfs_entries,
    get_lba_info,
    load_manifest,
    load_simple_yaml,
)


class TestLeoSplitExtract(unittest.TestCase):
    def make_manifest(self):
        return {
            "source_file": "test.ndd",
            "sector_size": 4,
            "file_count": 2,
            "files": [
                {
                    "file_id": 1,
                    "file_name": "BOOT",
                    "lba_start": 1,
                    "lba_length": 2,
                    "load_address": "0x80200000",
                    "entry_point": "0x80200010",
                },
                {
                    "file_id": 3,
                    "file_name": "NI/CHI:YOU BI",
                    "lba_start": 4,
                    "lba_length": 1,
                    "load_address": "0x80300000",
                    "entry_point": "0x80300000",
                },
            ],
        }

    def test_load_simple_yaml(self):
        text = """source_file: test.ndd
sector_size: 4
file_count: 1
files:
  - file_id: 1
    file_name: BOOT
    lba_start: 1
    lba_length: 2
    load_address: 0x80200000
    entry_point: 0x80200010
"""
        manifest = load_simple_yaml(text)
        self.assertEqual(manifest["sector_size"], 4)
        self.assertEqual(manifest["files"][0]["file_name"], "BOOT")
        self.assertEqual(manifest["files"][0]["lba_length"], 2)

    def test_load_json_manifest(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "manifest.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.make_manifest(), f)

            manifest = load_manifest(path)

        self.assertEqual(manifest["file_count"], 2)

    def test_extract_files(self):
        manifest = self.make_manifest()
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "test.ndd")
            output_dir = os.path.join(tmp_dir, "extracted")
            with open(image_path, "wb") as f:
                f.write(bytes(range(32)))

            results = extract_files(image_path, manifest, output_dir)

            self.assertEqual(len(results), 2)
            self.assertEqual(os.path.basename(results[0]["output"]), "01_BOOT.bin")
            self.assertEqual(os.path.basename(results[1]["output"]), "03_NI_CHI_YOU_BI.bin")
            with open(results[0]["output"], "rb") as f:
                self.assertEqual(f.read(), bytes(range(4, 12)))
            with open(results[1]["output"], "rb") as f:
                self.assertEqual(f.read(), bytes(range(16, 20)))
            with self.assertRaises(FileExistsError):
                extract_files(image_path, manifest, output_dir)

    def test_reject_out_of_range_entry(self):
        manifest = self.make_manifest()
        manifest["files"][0]["lba_start"] = 100
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "test.ndd")
            with open(image_path, "wb") as f:
                f.write(bytes(range(16)))

            with self.assertRaises(ValueError):
                extract_files(image_path, manifest, os.path.join(tmp_dir, "out"))

    def make_mfs_image(self, sector_size=256):
        data = bytearray(sector_size * 4292)
        file_lba = 1
        file_offset = file_lba * sector_size + 0x10
        payload = b"hello from mfs"
        data[file_offset : file_offset + len(payload)] = payload

        id_lba = 4291
        id_offset = id_lba * sector_size
        data[id_offset : id_offset + 10] = b"64dd-Multi"
        data[id_offset + 0x0A : id_offset + 0x0C] = b"02"
        data[id_offset + 0x0C : id_offset + 0x0E] = b"01"
        data[id_offset + 0x0F] = 6
        struct.pack_into(">H", data, id_offset + 0x28, 1)

        entry_offset = id_offset + 48
        struct.pack_into(">H", data, entry_offset + 0x00, 0x6000)
        struct.pack_into(">H", data, entry_offset + 0x02, 0)
        data[entry_offset + 0x04 : entry_offset + 0x06] = b"01"
        data[entry_offset + 0x06 : entry_offset + 0x0A] = b"TEST"
        struct.pack_into(">H", data, entry_offset + 0x0A, file_lba)
        struct.pack_into(">I", data, entry_offset + 0x0C, len(payload))
        data[entry_offset + 0x10 : entry_offset + 0x24] = b"keyword_pmotion2".ljust(20, b"\x00")
        data[entry_offset + 0x24 : entry_offset + 0x29] = b"bin\x00\x00"
        struct.pack_into(">H", data, entry_offset + 0x2A, 0x10)
        return bytes(data), payload

    def test_find_mfs_entries_from_rom_directory(self):
        data, payload = self.make_mfs_image()

        entries = find_mfs_entries(data, sector_size=256)

        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].name, "keyword_pmotion2")
        self.assertEqual(entries[0].file_type, "bin")
        self.assertEqual(entries[0].start_lba, 1)
        self.assertEqual(entries[0].data_offset, 0x10)
        self.assertEqual(entries[0].file_size, len(payload))

    def test_extract_mfs_files(self):
        data, payload = self.make_mfs_image()
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "test.ndd")
            output_dir = os.path.join(tmp_dir, "extracted")
            with open(image_path, "wb") as f:
                f.write(data)

            results = extract_mfs_files(image_path, output_dir, sector_size=256)

            self.assertEqual(len(results), 1)
            self.assertEqual(os.path.basename(results[0]["output"]), "01_rom_keyword_pmotion2.bin")
            with open(results[0]["output"], "rb") as f:
                self.assertEqual(f.read(), payload)

    def test_build_manifest_from_mfs(self):
        data, _ = self.make_mfs_image()
        with tempfile.TemporaryDirectory() as tmp_dir:
            image_path = os.path.join(tmp_dir, "test.ndd")
            with open(image_path, "wb") as f:
                f.write(data)

            manifest = build_manifest_from_mfs(image_path, sector_size=256)

        self.assertEqual(manifest["file_count"], 1)
        self.assertEqual(manifest["files"][0]["file_name"], "keyword_pmotion2.bin")
        self.assertEqual(manifest["files"][0]["block_offset"], 0x10)

    def test_full_ndd_lba_map(self):
        self.assertEqual(len(NDD_LBA_MAP), 4292)
        self.assertEqual(NDD_LBA_MAP[-1].offset + NDD_LBA_MAP[-1].size, NDD_IMAGE_SIZE)
        self.assertEqual(get_lba_info(0, NDD_IMAGE_SIZE).size, 19720)
        self.assertEqual(get_lba_info(4291, NDD_IMAGE_SIZE).size, 18360)


if __name__ == "__main__":
    unittest.main()
