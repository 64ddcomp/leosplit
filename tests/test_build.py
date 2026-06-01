import json
import os
import tempfile
import unittest

from leosplit.builder.leosplit_build import rebuild_image, sha1_file


class TestLeoSplitBuild(unittest.TestCase):
    def test_rebuild_image_patches_split_bins(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace_dir = os.path.join(tmp_dir, "split")
            bin_dir = os.path.join(workspace_dir, "bin")
            os.makedirs(bin_dir)

            base_path = os.path.join(tmp_dir, "base.ndd")
            output_path = os.path.join(tmp_dir, "rebuilt.ndd")
            expected = bytearray(range(32))
            with open(base_path, "wb") as f:
                f.write(expected)

            replacement = b"ABCD"
            expected[8:12] = replacement
            with open(os.path.join(bin_dir, "seg.bin"), "wb") as f:
                f.write(replacement)

            manifest = {
                "source_file": "base.ndd",
                "image_size": 32,
                "segments": [
                    {
                        "name": "seg",
                        "rom_offset": 8,
                        "size": 4,
                        "bin_path": "bin/seg.bin",
                    }
                ],
            }
            with open(os.path.join(workspace_dir, "leosplit_workspace.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            patched = rebuild_image(workspace_dir, output_path, base_path)

            self.assertEqual(patched[0]["name"], "seg")
            with open(output_path, "rb") as f:
                self.assertEqual(f.read(), bytes(expected))

    def test_rebuild_image_rejects_size_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace_dir = os.path.join(tmp_dir, "split")
            bin_dir = os.path.join(workspace_dir, "bin")
            os.makedirs(bin_dir)
            with open(os.path.join(bin_dir, "seg.bin"), "wb") as f:
                f.write(b"too long")
            with open(os.path.join(workspace_dir, "leosplit_workspace.json"), "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "image_size": 16,
                        "segments": [
                            {
                                "name": "seg",
                                "rom_offset": 0,
                                "size": 4,
                                "bin_path": "bin/seg.bin",
                            }
                        ],
                    },
                    f,
                )

            with self.assertRaises(ValueError):
                rebuild_image(workspace_dir, os.path.join(tmp_dir, "rebuilt.ndd"))

    def test_sha1_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, "data.bin")
            with open(path, "wb") as f:
                f.write(b"abc")

            self.assertEqual(sha1_file(path), "a9993e364706816aba3e25717850c26c9cd0d89d")


if __name__ == "__main__":
    unittest.main()
