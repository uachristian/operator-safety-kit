import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _helpers import ROOT, fake_bot_token, fake_github_token, fake_openai_key, fake_private_key_header
from guards import output_gate as og


class OutputGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self._env = mock.patch.dict(os.environ, {"HERMES_HOME": str(self.home)})
        self._env.start()
        os.environ.pop("OUTPUT_GATE_MODE", None)
        og.set_allowlist_file(ROOT / "guards" / "domain_allowlist.sample.txt")

    def tearDown(self):
        og.set_allowlist_file(None)
        self._env.stop()
        self._tmp.cleanup()

    def test_clean_message_allowed(self):
        v = og.check_message("ETA Friday, details at https://docs.example.com/x", skip_rate_limit=True)
        self.assertTrue(v.allowed)
        self.assertEqual(v.warnings, [])

    def test_secrets_hard_block_in_log_only(self):
        for s in (fake_openai_key(), fake_github_token(), fake_bot_token(), fake_private_key_header()):
            v = og.check_message("here: " + s, mode=og.MODE_LOG_ONLY, skip_rate_limit=True)
            self.assertFalse(v.allowed, s[:4])
            self.assertTrue(v.secrets_found)

    def test_suspicious_urls_hard_block(self):
        for url, label in (("http://" + "203.0.113.9" + ":8080", "raw_ip_url"),
                           ("https://" + "bit" + ".ly/abc", "url_shortener"),
                           ("https://xn--exmple-cua.com/login", "punycode_domain")):
            v = og.check_message("go " + url, skip_rate_limit=True)
            self.assertFalse(v.allowed, url)
            self.assertIn(label, v.suspicious_urls)

    def test_ip_literal_forms_all_hard_block(self):
        forms = [
            "http://" + "2130706433" + "/x",            # decimal
            "http://" + "0x7f" + "000001/x",              # hex
            "http://" + "0x7f.0x0.0x0.0x1/x",             # dotted hex
            "http://" + "0177.0.0.01/x",                  # octal
            "http://" + "127.1/x",                        # short form
            "http://" + "10.1.2/x",                       # three-part
            "https://[" + "::1" + "]:8443/x",              # ipv6 bracketed
            "http://[" + "2001:db8::7" + "]/x",
            "http://[" + "::ffff:" + "127.0.0.1" + "]/",   # v4-mapped v6
            "http://user@" + "198.51.100.4" + "/x",        # userinfo
            "HTTP://" + "203.0.113.9" + ".:80/",          # trailing dot + caps scheme
            "ftp://" + "203.0.113.9" + "/f",               # non-http scheme
        ]
        for url in forms:
            for mode in (og.MODE_LOG_ONLY, og.MODE_ENFORCE):
                v = og.check_message("go " + url, mode=mode, skip_rate_limit=True)
                self.assertFalse(v.allowed, (url, mode))
                self.assertIn("raw_ip_url", v.suspicious_urls, url)

    def test_numeric_looking_hostname_not_misparsed(self):
        v = og.check_message("https://docs.example.com/v1.2.3", mode=og.MODE_ENFORCE, skip_rate_limit=True)
        self.assertTrue(v.allowed, v.reasons)

    def test_unparseable_and_idn_urls(self):
        for url in ("http://[" + "zz::q" + "]/x", "http://" + "example.com" + ":99999/",
                    "http://a..b/", "file:///etc/passwd", "http://" + "1.2.3.4.5" + "/"):
            v = og.check_message("go " + url, mode=og.MODE_ENFORCE, skip_rate_limit=True)
            self.assertFalse(v.allowed, url)
        v = og.check_message("go http://" + "ex" + chr(0x0430) + "mple.com/", skip_rate_limit=True)
        self.assertFalse(v.allowed)
        self.assertIn("non_ascii_host", v.suspicious_urls)
        v = og.check_message("go file:///etc/passwd", mode=og.MODE_LOG_ONLY, skip_rate_limit=True)
        self.assertTrue(v.allowed)
        self.assertTrue(any(w.startswith("suspicious_url") for w in v.warnings))

    def test_novel_domain_warns_then_blocks(self):
        msg = "see https://unknown-site.test/page"
        self.assertTrue(og.check_message(msg, skip_rate_limit=True).allowed)
        v = og.check_message(msg, mode=og.MODE_ENFORCE, skip_rate_limit=True)
        self.assertFalse(v.allowed)
        self.assertEqual(v.novel_domains, ["unknown-site.test"])

    def test_suffix_lookalike_not_allowlisted(self):
        v = og.check_message("https://notexample.com/x", mode=og.MODE_ENFORCE, skip_rate_limit=True)
        self.assertFalse(v.allowed)

    def test_unknown_mode_fails_closed(self):
        v = og.check_message("x" * 5000, destination="telegram", mode="enforec", skip_rate_limit=True)
        self.assertEqual(v.mode, og.MODE_ENFORCE)
        self.assertFalse(v.allowed)

    def test_length_cap_per_destination(self):
        self.assertTrue(og.check_message("x" * 1700, destination="email", mode=og.MODE_ENFORCE, skip_rate_limit=True).allowed)
        self.assertFalse(og.check_message("x" * 1700, destination="sms:anything", mode=og.MODE_ENFORCE, skip_rate_limit=True).allowed)

    def test_rate_limit_and_state_under_hermes_home(self):
        with mock.patch.dict(og.RATE_LIMITS, {"burst": (2, 3600)}):
            results = [og.check_message("hi", agent="burst", mode=og.MODE_ENFORCE).allowed for _ in range(3)]
        self.assertEqual(results, [True, True, False])
        self.assertTrue((self.home / "security/state/rate_limits.json").exists())

    def test_audit_log_has_hash_not_text(self):
        secret_text = "top secret plan " + fake_openai_key()
        og.check_message(secret_text, skip_rate_limit=True)
        log = (self.home / "logs/output-gate.jsonl").read_text()
        self.assertNotIn("top secret plan", log)
        self.assertNotIn(fake_openai_key(), log)
        ev = json.loads(log.splitlines()[-1])
        self.assertEqual(len(ev["text_sha256"]), 64)
        self.assertEqual(ev["destination_class"], "generic")

    def test_record_write_scans_payload(self):
        v = og.check_record_write("crm_add_note", {"note": "key " + fake_openai_key()})
        self.assertFalse(v.allowed)


if __name__ == "__main__":
    unittest.main()
