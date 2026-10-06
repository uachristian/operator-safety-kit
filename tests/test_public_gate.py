import tempfile
import unittest
from pathlib import Path

from _helpers import (ROOT, fake_email, fake_github_token, fake_home_path, fake_local_secret,
                      fake_openai_key, fake_phone, fake_private_ip, fake_private_key_header, run_py)

GATE = ROOT / "tools" / "public_gate.py"


class PublicGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.tree = self.tmp / "tree"
        self.tree.mkdir()
        self.deny = self.tmp / "deny.txt"
        self.deny.write_text("# comment\nfrobnicator widgets\n")
        self.env = self.tmp / "dot.env"
        self.env.write_text("SOME_API_KEY=" + fake_local_secret() + "\nPROVIDER=openai-codex\n")

    def tearDown(self):
        self._tmp.cleanup()

    def gate(self, *extra):
        return run_py(GATE, self.tree, "--denylist", self.deny, "--env-glob", self.env, *extra)

    def test_clean_tree_passes(self):
        (self.tree / "README.md").write_text("hello, see https://example.com\n")
        r = self.gate()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("0 findings", r.stdout)

    def test_empty_scan_exits_2(self):
        r = self.gate()
        self.assertEqual(r.returncode, 2)
        self.assertIn("empty scan", r.stdout)

    def test_binary_only_tree_is_empty_scan(self):
        (self.tree / "blob.bin").write_bytes(b"\0\1\2")
        r = self.gate()
        self.assertEqual(r.returncode, 2)

    def test_planted_values_each_detected_without_echo(self):
        planted = {
            "token_shape": fake_openai_key(),
            "home_path": fake_home_path(),
            "email": fake_email(),
            "private_ip": fake_private_ip(),
            "phone": fake_phone(),
            "exact_local_secret": "x = '" + fake_local_secret() + "'",
            "denylist_term": "Built by Frobnicator Widgets",
        }
        for i, (cat, value) in enumerate(planted.items()):
            (self.tree / f"f{i}.txt").write_text("line one\n" + value + "\n")
        r = self.gate()
        self.assertEqual(r.returncode, 1)
        for cat in planted:
            self.assertIn(f"FAIL {cat}", r.stdout, cat)
        for value in (fake_openai_key(), fake_local_secret(), fake_email(), fake_private_ip()):
            self.assertNotIn(value, r.stdout)
        self.assertIn(":2", r.stdout)  # reports path:line

    def test_private_key_and_github_token(self):
        (self.tree / "a.txt").write_text(fake_private_key_header() + "\n" + fake_github_token() + "\n")
        r = self.gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("token_shape: 2", r.stdout)

    def test_forbidden_filenames(self):
        (self.tree / "ok.md").write_text("fine\n")
        (self.tree / ".env").write_text("A=b\n")
        (self.tree / "server.pem").write_text("x\n")
        (self.tree / ".env.example").write_text("A=\n")
        r = self.gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("forbidden_path: 2", r.stdout)

    def test_symlink_flagged(self):
        (self.tree / "ok.md").write_text("fine\n")
        (self.tree / "link").symlink_to(self.tree / "ok.md")
        r = self.gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("symlink", r.stdout)

    def test_example_email_and_identifier_env_values_allowed(self):
        (self.tree / "a.md").write_text("contact: ops" + "@" + "example.com\nprovider openai-codex\n")
        r = self.gate()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_email_exceptions_case_insensitive_but_strict(self):
        at = "@"
        (self.tree / "a.md").write_text("Pat" + at + "Example.com\nops" + at + "EXAMPLE.ORG\n"
                                        "1+dev" + at + "Users.NoReply.GitHub.com\n")
        self.assertEqual(self.gate().returncode, 0)
        for bad in ("a" + at + "example.com.evil.io", "a" + at + "Example.community"):
            (self.tree / "b.md").write_text(bad + "\n")
            r = self.gate()
            self.assertEqual(r.returncode, 1, bad)
            self.assertIn("FAIL email", r.stdout)

    def test_no_waiver_flag(self):
        (self.tree / "a.txt").write_text(fake_openai_key() + "\n")
        r = self.gate("--allow", "token_shape:a.txt")
        self.assertEqual(r.returncode, 2)  # argparse rejects the removed flag
        self.assertEqual(self.gate().returncode, 1)

    def test_google_key_and_chat_id(self):
        (self.tree / "a.txt").write_text("k = " + "AI" + "za" + "B" * 35 + "\nchat = " + "-100" + "1234567890\n")
        r = self.gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("token_shape", r.stdout)
        self.assertIn("telegram_or_slack_id", r.stdout)

    def test_git_identity_checked(self):
        import subprocess
        from _helpers import git_env
        (self.tree / "a.md").write_text("fine\n")
        env = git_env(self.tmp)
        env["GIT_AUTHOR_EMAIL"] = "dev" + "@" + "corp-internal.io"
        subprocess.run(["git", "init", "-q", str(self.tree)], check=True, env=env)
        subprocess.run(["git", "-C", str(self.tree), "add", "-A"], check=True, env=env)
        subprocess.run(["git", "-C", str(self.tree), "commit", "-qm", "init"], check=True, env=env)
        r = self.gate()
        self.assertEqual(r.returncode, 1)
        self.assertIn("identity_not_noreply", r.stdout)


if __name__ == "__main__":
    unittest.main()
