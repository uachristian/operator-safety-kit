import subprocess
import tempfile
import unittest
from pathlib import Path

from _helpers import (ROOT, fake_email, fake_local_secret, fake_openai_key, git, git_env,
                      load_module, run_py)

GATE = ROOT / "tools" / "privacy_gate.py"


class PrivacyGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        self.env = git_env(self.tmp)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True, env=self.env)
        self.deny = self.tmp / "deny.txt"
        self.deny.write_text("frobnicator widgets\nre:\\bQQ[0-9]{6}\\b\n")
        self.envfile = self.tmp / "x.env"
        self.envfile.write_text("SERVICE_TOKEN=" + fake_local_secret() + "\n")

    def tearDown(self):
        self._tmp.cleanup()

    def commit(self, name, content, msg="add file", env=None):
        (self.repo / name).write_text(content)
        git(self.repo, "add", "-A", env=env or self.env)
        git(self.repo, "commit", "-qm", msg, env=env or self.env)
        return git(self.repo, "rev-parse", "HEAD", env=self.env).strip()

    def gate(self, *revs):
        return run_py(GATE, "--repo", self.repo, "--denylist", self.deny,
                      "--env-glob", self.envfile, *revs, env=self.env)

    def test_clean_commit_passes(self):
        c = self.commit("a.md", "hello\n")
        r = self.gate(c)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("PASS", r.stdout)

    def test_no_revs_is_exit_2(self):
        self.commit("a.md", "x\n")
        r = self.gate()
        self.assertEqual(r.returncode, 2)

    def test_unresolvable_rev_is_exit_2(self):
        self.commit("a.md", "x\n")
        r = self.gate("does-not-exist")
        self.assertEqual(r.returncode, 2)

    def test_empty_range_is_exit_2(self):
        c = self.commit("a.md", "x\n")
        r = self.gate(f"{c}..{c}")
        self.assertEqual(r.returncode, 2)

    def test_added_lines_scanned(self):
        base = self.commit("a.md", "x\n")
        self.commit("b.py", "k = '" + fake_openai_key() + "'\nowner = 'Frobnicator_Widgets'\nchat = QQ123456\n"
                    "s = '" + fake_local_secret() + "'\n")
        r = self.gate(f"{base}..HEAD")
        self.assertEqual(r.returncode, 1)
        for cat in ("token_shape", "denylist_term", "exact_local_secret"):
            self.assertIn(cat, r.stdout)
        self.assertIn("b.py:1", r.stdout)
        self.assertNotIn(fake_openai_key(), r.stdout)
        self.assertNotIn(fake_local_secret(), r.stdout)

    def test_google_key_chat_id_and_case_insensitive_email_exceptions(self):
        at = "@"
        base = self.commit("a.md", "x\n")
        c = self.commit("ok.md", "Pat" + at + "Example.com\n1+x" + at + "Users.NoReply.GitHub.com\n")
        self.assertEqual(self.gate(f"{base}..{c}").returncode, 0)
        self.commit("bad.md", "k = " + "AI" + "za" + "C" * 35 + "\nid " + "-100" + "9876543210\n")
        r = self.gate(f"{c}..HEAD")
        self.assertEqual(r.returncode, 1)
        self.assertIn("token_shape", r.stdout)
        self.assertIn("telegram_or_slack_id", r.stdout)

    def test_removed_lines_not_flagged(self):
        self.commit("b.md", "frobnicator widgets\n")
        base = git(self.repo, "rev-parse", "HEAD", env=self.env).strip()
        self.commit("b.md", "clean\n")
        r = self.gate(f"{base}..HEAD")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_commit_message_and_identity(self):
        env = dict(self.env)
        env["GIT_AUTHOR_EMAIL"] = fake_email()
        c = self.commit("a.md", "ok\n", msg="fix for frobnicator widgets", env=env)
        r = self.gate(c)
        self.assertEqual(r.returncode, 1)
        self.assertIn("identity_not_noreply", r.stdout)
        self.assertIn("<message>", r.stdout)

    def test_no_hardcoded_owner_terms(self):
        mod = load_module("tools/privacy_gate.py", "pg_mod")
        self.assertEqual(set(mod.PATTERNS), {"home_path", "email", "tailnet", "private_ip", "phone", "token_shape",
                                             "telegram_or_slack_id"})
        self.assertEqual(mod.load_denylist(None), [])

    def test_default_paths_follow_hermes_home(self):
        import os
        from unittest import mock
        mod = load_module("tools/privacy_gate.py", "pg_mod2")
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(self.tmp / "hh")}):
            self.assertIsNone(mod.default_denylist())
            (self.tmp / "hh/state/public-repos").mkdir(parents=True)
            (self.tmp / "hh/state/public-repos/denylist.txt").write_text("x\n")
            self.assertTrue(mod.default_denylist().startswith(str(self.tmp)))
            self.assertTrue(all(g.startswith(str(self.tmp)) for g in mod.default_env_globs()))


if __name__ == "__main__":
    unittest.main()
