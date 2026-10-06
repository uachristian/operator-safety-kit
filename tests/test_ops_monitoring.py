import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _helpers import ROOT


def load_with_root(rel, name, root):
    with mock.patch.dict(os.environ, {"HERMES_FLEET_ROOT": str(root)}):
        spec = importlib.util.spec_from_file_location(name, ROOT / rel)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class FleetHealthTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "fleet"
        (self.root / "profiles/ops").mkdir(parents=True)
        (self.root / "profiles/ops/critical_labels.txt").write_text("# c\n^com\\.example\\.billing$\n(bad\n")
        self.fh = load_with_root("ops-monitoring/fleet_health.py", "fh_t", self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_root_and_profile_paths(self):
        self.assertEqual(self.fh.ROOT, self.root)
        self.assertEqual(self.fh.OPS, self.root / "profiles" / "ops")

    def test_profile_scoped_hermes_home_lifts_to_install_root(self):
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(self.root / "profiles" / "ops")}):
            os.environ.pop("HERMES_FLEET_ROOT", None)
            spec = importlib.util.spec_from_file_location("fh_t2", ROOT / "ops-monitoring/fleet_health.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        self.assertEqual(mod.ROOT, self.root)

    def test_log_example_is_fingerprint_only(self):
        raw = ("2026-07-10T10:00:00Z ERROR RequestException HTTP 500 Authorization: Bearer abc "
               "user" + "@" + "example.com https://vendor.example/path?api_key=secretvalue")
        out = self.fh.safe_log_example("gateway.log", raw)
        self.assertIn("exception=RequestException", out)
        self.assertIn("http=500", out)
        self.assertRegex(out, r"fingerprint=[0-9a-f]{16}")
        for s in ("secretvalue", "example.com", "api_key", "Bearer"):
            self.assertNotIn(s, out)

    def test_critical_labels_and_extra_file(self):
        self.assertTrue(self.fh.is_critical_label("ai.hermes.gateway-ops"))
        self.assertTrue(self.fh.is_critical_label("com.example.billing"))
        self.assertTrue(self.fh.is_critical_label("com.example.intake-webhook"))
        self.assertFalse(self.fh.is_critical_label("com.example.unrelated"))

    def test_no_owner_specific_defaults(self):
        self.assertFalse(self.fh.is_critical_label("com.example.guardian"))
        self.assertFalse(self.fh.is_critical_label("com.example.error-watcher"))
        noise, skips = self.fh.load_tuning(self.root / "absent.json")
        self.assertEqual(skips, {})
        self.assertFalse(noise.search("Telegram polling resumed after network error"))
        self.assertTrue(noise.search("call failed: 502 Bad Gateway"))

    def test_tuning_file_noise_and_skips(self):
        ops = self.root / "profiles/ops"
        (ops / "fleet_health.json").write_text(json.dumps(
            {"noise_patterns": ["known flaky thing", "(bad"], "skip_logs": {"ops": ["logs/skip.log"]}}))
        (ops / "logs").mkdir()
        (ops / "logs/skip.log").write_text("ERROR boom\n")
        (ops / "logs/a.log").write_text("ERROR known flaky thing\nERROR real problem\n")
        out = self.fh.log_findings({"name": "ops", "path": str(ops)})
        self.assertEqual(out["actionable_count"], 1)
        self.assertEqual(out["noisy_count"], 1)
        self.assertEqual(out["sources"], ["logs/a.log"])

    def test_example_monitors_use_neutral_ports(self):
        data = json.loads((ROOT / "ops-monitoring/examples/monitors.d/core-endpoints.example.json").read_text())
        ports = {m.get("port") for m in data["monitors"]} | {
            int(m["url"].split(":")[2].split("/")[0]) for m in data["monitors"] if m.get("url", "").count(":") == 2}
        self.assertTrue(ports - {None} <= {8080, 9000}, ports)

    def test_inventory_drift_and_ephemeral_jobs(self):
        new = self.fh.compute_new_inventory({"profiles": ["a", "b"], "monitors": []}, {"profiles": ["a"]})
        self.assertEqual(new, {"profiles": ["b"]})
        self.assertFalse(self.fh.inventory_tracks_cron_job({"schedule": {"kind": "once"}}))
        self.assertFalse(self.fh.inventory_tracks_cron_job({"repeat": {"times": 1}}))
        self.assertTrue(self.fh.inventory_tracks_cron_job({"schedule": {"kind": "cron"}}))

    def test_scripts_summary_detects_syntax_failures(self):
        p = self.root / "profiles/ops"
        (p / "scripts").mkdir()
        (p / "scripts/good.py").write_text("x = 1\n")
        (p / "scripts/bad.py").write_text("def (:\n")
        (p / "scripts/bad.sh").write_text("if then fi\n")
        s = self.fh.scripts_summary({"path": str(p)})
        self.assertEqual(len(s["py_fail"]), 1)
        self.assertEqual(len(s["sh_fail"]), 1)

    def test_env_summary_reports_mode_not_values(self):
        p = self.root / "profiles/ops"
        (p / ".env").write_text("A_TOKEN=zzzz\n")
        os.chmod(p / ".env", 0o644)
        e = self.fh.env_summary({"path": str(p)})
        self.assertEqual(e, {"present": True, "mode": "0o644", "key_count": 1})

    def test_markdown_critical_only_silent_when_healthy(self):
        report = {"issues": [], "new_inventory": {}, "fleet_status": "green", "timestamp": "t",
                  "profiles": [], "launchd": {}, "plists": {}, "monitors": []}
        self.assertEqual(self.fh.render_markdown(report, critical_only=True), "")
        report["issues"] = [{"severity": "critical", "where": "x", "issue": "down"}]
        self.assertIn("Critical:", self.fh.render_markdown(report, critical_only=True))


class CronPreflightTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "fleet"
        ops = self.root / "profiles/ops"
        (ops / "scripts").mkdir(parents=True)
        (ops / "cron").mkdir()
        (self.root / "scripts").mkdir()
        (ops / "scripts/ok.sh").write_text("#!/bin/bash\necho ok\n")
        os.chmod(ops / "scripts/ok.sh", 0o755)
        (ops / "scripts/noexec.sh").write_text("#!/bin/bash\necho\n")
        (ops / "scripts/broken.py").write_text("def (:\n")
        jobs = [
            {"id": "1", "name": "ok", "script": "ok.sh"},
            {"id": "2", "name": "missing", "script": "missing.sh"},
            {"id": "3", "name": "noexec", "script": "noexec.sh"},
            {"id": "4", "name": "broken", "script": "broken.py"},
            {"id": "5", "name": "paused-missing", "script": "nope.sh", "paused": True},
            {"id": "6", "name": "prompt-only", "prompt": "hi"},
        ]
        (ops / "cron/jobs.json").write_text(json.dumps({"jobs": jobs}))
        self.cp = load_with_root("ops-monitoring/cron_preflight.py", "cp_t", self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_scan_classifies_jobs(self):
        rep = self.cp.scan()
        codes = sorted((i["job_id"], i["code"], i["severity"]) for i in rep["issues"])
        self.assertEqual(codes, [
            ("2", "missing_resolved_script", "critical"),
            ("3", "script_not_executable", "critical"),
            ("4", "script_syntax_failed", "critical"),
            ("5", "missing_resolved_script", "warning"),
        ])
        self.assertEqual(rep["summary"]["script_jobs"], 5)
        self.assertEqual(rep["summary"]["enabled_script_jobs"], 4)
        self.assertEqual(rep["status"], "red")

    def test_job_name_never_uses_prompt_text(self):
        self.assertEqual(self.cp.job_name({"prompt": "private instructions here"}), "<unnamed>")
        self.assertEqual(self.cp.job_name({"id": "j9", "prompt": "secret"}), "j9")
        self.assertEqual(self.cp.job_name({"name": "nightly", "prompt": "secret"}), "nightly")
        self.assertEqual(self.cp.job_id({"prompt": "secret"}), "<unnamed>")
        rep = json.dumps(self.cp.scan())
        self.assertNotIn('"hi"', rep)

    def test_root_wrapper_proposal(self):
        (self.root / "scripts/missing.sh").write_text("#!/bin/bash\n")
        rep = self.cp.scan()
        prop = [i["proposal"] for i in rep["issues"] if i["job_id"] == "2"][0]
        self.assertIn("wrapper", prop)

    def test_stale_script_not_found_metadata_ignored_once_path_exists(self):
        p = self.root / "profiles/ops/scripts/ok.sh"
        self.assertIsNone(self.cp.recent_script_not_found({"last_error": "boom"}))
        self.assertEqual(self.cp.recent_script_not_found({"last_error": f"Script not found: {p}"}), str(p))


if __name__ == "__main__":
    unittest.main()
