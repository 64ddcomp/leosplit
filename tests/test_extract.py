import json
import os
import tempfile
import unittest

from leosplit_extract import extract_files, load_manifest, load_simple_yaml


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


if __name__ == "__main__":
    unittest.main()
