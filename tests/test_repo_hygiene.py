"""Repo-level invariants: no hardcoded owner home paths, samples exist, every
script compiles. Runs offline against this tree only."""
import py_compile
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import ROOT

SKIP = {".git", "__pycache__"}


def files(suffixes):
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP) and (p.suffix in suffixes or p.name in suffixes):
            yield p


class HygieneTests(unittest.TestCase):
    def test_python_compiles(self):
        with tempfile.TemporaryDirectory() as d:
            for p in files({".py"}):
                py_compile.compile(str(p), cfile=str(Path(d) / (p.name + "c")), doraise=True)

    def test_shell_syntax(self):
        for p in list(files({".sh"})) + [ROOT / "hooks/pre-push.sample"]:
            r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{p.name}: {r.stderr}")

    def test_no_hardcoded_hermes_home_in_code(self):
        rx = re.compile(r"""Path\.home\(\)\s*/\s*["']\.hermes["']\s*/""")
        for p in files({".py"}):
            if p.parent.name == "tests":
                continue
            self.assertIsNone(rx.search(p.read_text()), f"{p.name} hardcodes a subpath of ~/.hermes")

    def test_required_files_present(self):
        for rel in ("README.md", "LICENSE", ".gitignore", "tools/public_gate.py", "tools/privacy_gate.py",
                    "tools/denylist.example.txt", "guards/wrap_untrusted.py", "guards/output_gate.py",
                    "guards/capability_gate.py", "ops-monitoring/fleet_health.py",
                    "ops-monitoring/cron_preflight.py", "ops-monitoring/ops-profile-SOUL.template.md",
                    "templates/backup-and-rollback.md", "templates/incident-report.md",
                    "templates/pre-push-checklist.md", "hooks/pre-push.sample"):
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_example_json_parses(self):
        import json
        for p in files({".json"}):
            json.loads(p.read_text())

    def test_license_header(self):
        self.assertIn("Copyright (c) 2026 uachristian", (ROOT / "LICENSE").read_text())


if __name__ == "__main__":
    unittest.main()
