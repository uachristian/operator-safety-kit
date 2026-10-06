import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _helpers import ROOT, git, git_env, load_module, run_py

snap = load_module("edit-safety/edit_safety_snapshot.py", "edit_safety_snapshot_t")
drift = load_module("edit-safety/drift_watch.py", "drift_watch_t")


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._env = mock.patch.dict(os.environ, git_env(self.tmp))
        self._env.start()
        self.src = self.tmp / "skills"
        (self.src / "cat/one").mkdir(parents=True)
        (self.src / "cat/one/SKILL.md").write_text("v1\n")
        self.cfg = {"repo": str(self.tmp / "safety"),
                    "tracked": [{"base": str(self.src), "pattern": "*/*/SKILL.md", "prefix": "skills"},
                                {"base": str(self.tmp / "absent"), "pattern": "*", "prefix": "gone"}]}

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def test_snapshot_commits_only_on_change(self):
        r1 = snap.snapshot(self.cfg, "t1")
        self.assertTrue(r1["changed"])
        self.assertIn("missing:gone", r1["skipped"])
        self.assertFalse(snap.snapshot(self.cfg, "t2")["changed"])
        (self.src / "cat/one/SKILL.md").write_text("v2\n")
        self.assertTrue(snap.snapshot(self.cfg, "t3")["changed"])
        log = git(Path(self.cfg["repo"]), "log", "--oneline")
        self.assertEqual(len(log.splitlines()), 2)

    def test_empty_source_keeps_last_good_snapshot(self):
        snap.snapshot(self.cfg, "t1")
        (self.src / "cat/one/SKILL.md").unlink()
        r = snap.snapshot(self.cfg, "t2")
        self.assertIn("empty:skills", r["skipped"])
        self.assertTrue((Path(self.cfg["repo"]) / "snapshot/skills/cat/one/SKILL.md").exists())

    def test_default_config_follows_hermes_home(self):
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(self.tmp / "hh")}):
            cfg = snap.default_config()
        self.assertTrue(cfg["repo"].startswith(str(self.tmp)))
        self.assertTrue(all(t["base"].startswith(str(self.tmp)) for t in cfg["tracked"]))

    def test_default_tracks_root_soul_and_repo_is_private(self):
        hh = self.tmp / "hh"
        (hh / "profiles/ops").mkdir(parents=True)
        (hh / "SOUL.md").write_text("root soul\n")
        (hh / "profiles/ops/SOUL.md").write_text("ops soul\n")
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(hh)}):
            cfg = snap.default_config()
        self.assertIn({"base": str(hh), "pattern": "SOUL.md", "prefix": "root"}, cfg["tracked"])
        old = os.umask(0o022)
        try:
            snap.snapshot(cfg, "t")
        finally:
            os.umask(old)
        repo = Path(cfg["repo"])
        self.assertTrue((repo / "snapshot/root/SOUL.md").exists())
        self.assertTrue((repo / "snapshot/profiles/ops/SOUL.md").exists())
        self.assertEqual(repo.stat().st_mode & 0o777, 0o700)

    def test_periodic_wrapper_runs_with_lock_and_log(self):
        cfgp = self.tmp / "cfg.json"
        cfgp.write_text(json.dumps(self.cfg))
        env = dict(os.environ, HERMES_HOME=str(self.tmp / "hh"), PYTHONDONTWRITEBYTECODE="1")
        sh = ROOT / "edit-safety/edit-safety-periodic-snapshot.sh"
        r = subprocess.run(["bash", str(sh), "--config", str(cfgp)], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("snapshot finished", (self.tmp / "hh/logs/edit-safety-watch.log").read_text())
        (self.tmp / "hh/state/edit-safety-snapshot.lock").mkdir()
        r = subprocess.run(["bash", str(sh), "--config", str(cfgp)], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("lock held", (self.tmp / "hh/logs/edit-safety-watch.log").read_text())


class DriftTests(unittest.TestCase):
    def test_decide_hysteresis(self):
        s, out = drift.decide({}, ["a"])
        self.assertEqual(out, [])
        s, out = drift.decide(s, ["a"])
        self.assertIn("- a", out)
        s, out = drift.decide(s, ["a"])
        self.assertEqual(out, [])  # already alerted
        s, out = drift.decide(s, [])
        self.assertIn("resolved", out[0])
        s, out = drift.decide(s, [])
        self.assertEqual(out, [])

    def test_transient_issue_never_alerts(self):
        s, out = drift.decide({}, ["flap"])
        s, out = drift.decide(s, [])
        self.assertEqual(out, [])

    def test_collect_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            env = git_env(d)
            repo, live = d / "repo", d / "live"
            (repo / "skills/a").mkdir(parents=True)
            (repo / "skills/a/SKILL.md").write_text("same\n")
            (repo / "skills/b.md").write_text("repo\n")
            subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
            git(repo, "add", "-A", env=env)
            git(repo, "commit", "-qm", "x", env=env)
            (live / "a").mkdir(parents=True)
            (live / "a/SKILL.md").write_text("same   \n")  # whitespace-only diff on .md
            (live / "b.md").write_text("edited live\n")
            (live / "extra.py").write_text("x = 1\n")
            cfg = {"mappings": [{"name": "m", "repo": str(repo), "repo_prefix": "skills",
                                 "live_root": str(live), "detect_extras": True}]}
            issues = drift.collect(cfg)
            self.assertEqual(issues, ["m: live differs b.md", "m: unmirrored live file extra.py"])
            cfgp = d / "c.json"
            cfgp.write_text(json.dumps(cfg))
            env["HERMES_HOME"] = str(d / "hh")
            r = run_py(ROOT / "edit-safety/drift_watch.py", "--config", cfgp, env=env)
            self.assertEqual((r.returncode, r.stdout), (0, ""))
            r = run_py(ROOT / "edit-safety/drift_watch.py", "--config", cfgp, env=env)
            self.assertIn("2 new issue", r.stdout)
            self.assertTrue((d / "hh/state/drift-watch/state.json").exists())


if __name__ == "__main__":
    unittest.main()
