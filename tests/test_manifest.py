import io
import os
import struct
import unittest

from leosplit_manifest import (
    find_dol_candidates,
    find_n64dd_load_table_entries,
    format_hex,
    parse_dol_header,
)


def make_test_dol() -> bytes:
    # Build a minimal DOL-like header with one text segment and a valid entry point.
    data = bytearray(0x100)
    struct.pack_into(">I", data, 0x00, 0x100)  # text offset
    struct.pack_into(">I", data, 0x4C, 0x80001000)  # text load address
    struct.pack_into(">I", data, 0xA0, 0x10)  # text size
    struct.pack_into(">I", data, 0xF8, 0x80001000)  # entry point
    data.extend(b"A" * 0x10)
    return bytes(data)


class TestLeoSplitManifest(unittest.TestCase):
    def test_parse_dol_header(self):
        dol = make_test_dol()
        result = parse_dol_header(dol, 0)
        self.assertIsNotNone(result)
        self.assertEqual(result["entry_point"], 0x80001000)
        self.assertEqual(result["load_address"], 0x80001000)
        self.assertEqual(result["file_size"], 0x110)

    def test_find_dol_candidates(self):
        dol = make_test_dol()
        candidates = find_dol_candidates(dol, sector_size=2048)
        self.assertEqual(len(candidates), 1)
        entry = candidates[0]
        self.assertEqual(entry.lba_start, 0)
        self.assertEqual(entry.lba_length, 1)
        self.assertEqual(entry.load_address, 0x80001000)
        self.assertEqual(entry.entry_point, 0x80001000)

    def test_find_n64dd_load_table_entries(self):
        data = bytearray(0x300)
        data[0x40:0x52] = b"keyword_pmotion2\x00"
        struct.pack_into(">IIIIII", data, 0x80, 0x2B, 0x2C, 0x80218980, 0x8021F310, 0x802189D0, 0x8021F310)
        struct.pack_into(">IIIIII", data, 0xA0, 0x40E, 0x413, 0x802FF800, 0x8032D5A0, 0x803124C0, 0x8032D5A0)

        candidates = find_n64dd_load_table_entries(bytes(data))

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].file_name, "keyword_pmotion2")
        self.assertEqual(candidates[0].lba_start, 0x2B)
        self.assertEqual(candidates[0].lba_length, 1)
        self.assertEqual(candidates[0].load_address, 0x80218980)
        self.assertEqual(candidates[0].entry_point, 0x802189D0)
        self.assertEqual(candidates[1].lba_start, 0x40E)
        self.assertEqual(candidates[1].lba_length, 5)

    def test_format_hex(self):
        self.assertEqual(format_hex(0x80000000), "0x80000000")


if __name__ == "__main__":
    unittest.main()
