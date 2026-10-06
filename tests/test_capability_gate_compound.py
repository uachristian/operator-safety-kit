import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from guards import capability_gate as cg


class CompoundReadNameTests(unittest.TestCase):
    def test_read_prefixed_names_with_write_verbs_are_writes(self):
        for name in ["search_replace", "find_and_replace", "lookup_and_save", "list_and_upload",
                     "get_upload", "view_and_rename", "get_commit", "get_trigger", "read_or_write"]:
            self.assertTrue(cg.is_write_tool(name), name)

    def test_plain_reads_still_reads(self):
        for name in ["read_file", "search_files", "get_order", "list_contacts", "web_search"]:
            self.assertFalse(cg.is_write_tool(name), name)


if __name__ == "__main__":
    unittest.main()
