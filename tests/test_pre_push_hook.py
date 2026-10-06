import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import ROOT, git, git_env

HOOK = ROOT / "hooks" / "pre-push.sample"


class PrePushHookTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.env = git_env(self.tmp)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=self.env)
        (self.repo / "README.md").write_text("hello\n")
        git(self.repo, "add", "-A", env=self.env)
        git(self.repo, "commit", "-qm", "init", env=self.env)
        self.env.update({"HERMES_HOME": str(self.tmp / "hh"), "SAFETY_KIT_DIR": str(ROOT),
                         "PYTHONDONTWRITEBYTECODE": "1", "PUBLIC_GATE_ENV_GLOBS": str(self.tmp / "none.env")})
        self.env.pop("SAFETY_KIT_ALLOW_NO_DENYLIST", None)
        self.env.pop("PUBLIC_GATE_DENYLIST", None)

    def tearDown(self):
        self._tmp.cleanup()

    def run_hook(self, **extra):
        env = dict(self.env, **extra)
        return subprocess.run(["bash", str(HOOK)], cwd=str(self.repo), env=env, input="",
                              capture_output=True, text=True)

    def test_bash_syntax(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(HOOK)]).returncode, 0)

    def test_missing_denylist_blocks(self):
        r = self.run_hook()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("BLOCKED no denylist", r.stderr)

    def test_explicit_opt_out_allows_generic_only(self):
        r = self.run_hook(SAFETY_KIT_ALLOW_NO_DENYLIST="1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("WARNING", r.stderr)

    def test_opt_out_must_be_exactly_1(self):
        self.assertNotEqual(self.run_hook(SAFETY_KIT_ALLOW_NO_DENYLIST="yes").returncode, 0)

    def test_with_denylist_passes(self):
        deny = self.tmp / "deny.txt"
        deny.write_text("frobnicator widgets\n")
        r = self.run_hook(PUBLIC_GATE_DENYLIST=str(deny))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_missing_privacy_gate_blocks(self):
        kit = self.tmp / "kit"
        (kit / "tools").mkdir(parents=True)
        shutil.copy(ROOT / "tools/public_gate.py", kit / "tools/public_gate.py")
        r = self.run_hook(SAFETY_KIT_DIR=str(kit), SAFETY_KIT_ALLOW_NO_DENYLIST="1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("privacy_gate.py not found", r.stderr)


if __name__ == "__main__":
    unittest.main()
