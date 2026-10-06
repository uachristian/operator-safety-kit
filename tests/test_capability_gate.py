import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _helpers import ROOT  # noqa: F401
from guards import capability_gate as cg

SESSION_KEYS = ("HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID", "HERMES_SESSION_MESSAGE_ID", "HERMES_CRON_SESSION")


class CapabilityGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        clean = {k: v for k, v in os.environ.items() if k not in SESSION_KEYS}
        clean["HERMES_HOME"] = str(self.home)
        self._env = mock.patch.dict(os.environ, clean, clear=True)
        self._env.start()
        cg.set_owner_ids(None)
        cg.set_session_reader(None)
        cg.set_denial_notifier(None)
        (self.home / "security").mkdir()
        (self.home / "security/owner_ids.json").write_text(json.dumps({"telegram": ["1001"]}))

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def session(self, platform="", user="", msg="", cron=False):
        os.environ.update({"HERMES_SESSION_PLATFORM": platform, "HERMES_SESSION_USER_ID": user,
                           "HERMES_SESSION_MESSAGE_ID": msg})
        if cron:
            os.environ["HERMES_CRON_SESSION"] = "1"

    def test_write_detection(self):
        self.assertTrue(cg.is_write_tool("crm_update_contact", "crm"))
        self.assertTrue(cg.is_write_tool("send_message"))
        self.assertFalse(cg.is_write_tool("crm_get_contact", "crm"))
        self.assertFalse(cg.is_write_tool("crm_search_orders", "crm"))

    def test_write_detection_fails_closed(self):
        writes = ("write_file", "terminal", "execute_code", "patch", "approve_payment",
                  "transfer_funds", "deploy", "upsert_contact", "upsertContact", "approvePayment",
                  "transfer-funds", "Deploy-Service", "frobnicate", "", "   ", "do_thing",
                  "get_and_delete_item", "listAndPurge", "search_replace_write", "mcp_crm_delete_contact",
                  "crm_get_contact")  # no server given: unknown prefix -> write
        for name in writes:
            self.assertTrue(cg.is_write_tool(name), repr(name))
        reads = ("read_file", "search_files", "web_search", "web_extract", "session_search",
                 "skill_view", "skills_list", "get_order", "list_users", "search_orders",
                 "find_part", "view_ticket", "show_status", "describe_table", "lookup_vin",
                 "getOrder", "listUsers", "search-orders", "ReadFile", "webSearch", "skills-list",
                 "getHTTPStatus")
        for name in reads:
            self.assertFalse(cg.is_write_tool(name), name)
        self.assertFalse(cg.is_write_tool("mcp_crm_get_contact", "crm"))
        self.assertTrue(cg.is_write_tool("mcp_crm_upsert_contact", "crm"))

    def test_read_allowlist_extensible_via_config(self):
        self.assertTrue(cg.is_write_tool("crm_dump_report"))
        (self.home / "security/read_tool_allowlist.txt").write_text(
            "# extras\ncrm_dump_report\nprefix:fetch\n")
        self.assertFalse(cg.is_write_tool("crm_dump_report"))
        self.assertFalse(cg.is_write_tool("fetchInvoice"))
        self.assertTrue(cg.is_write_tool("fetch_and_delete"))

    def test_missing_context_is_least_privilege(self):
        self.assertEqual(cg.resolve_tier()[0], "unknown")
        self.assertIsNone(cg.check_tool_call("crm", "crm_get_contact"))
        d = cg.check_tool_call("crm", "crm_delete_contact")
        self.assertEqual(d["type"], "TierDenied")
        self.assertEqual(d["tier"], "unknown")
        self.assertIsNotNone(cg.check_tool_call("x", "write_file"))

    def test_unknown_platform_and_missing_user_not_owner(self):
        for plat, user in (("bogus", ""), ("telegram", ""), ("", "1001"), ("CLI-ish", "")):
            os.environ.update({"HERMES_SESSION_PLATFORM": plat, "HERMES_SESSION_USER_ID": user})
            self.assertNotEqual(cg.resolve_tier()[0], "owner", (plat, user))
        # whitelist does not apply to unknown tier
        (self.home / "security/team_write_whitelist.txt").write_text("write_file\n")
        self.session("", "")
        self.assertIsNotNone(cg.check_tool_call("x", "write_file"))

    def test_explicit_local_platform_is_owner(self):
        for plat in ("cli", "local", "desktop", "CLI"):
            self.session(plat)
            self.assertEqual(cg.resolve_tier()[0], "owner", plat)
            self.assertIsNone(cg.check_tool_call("crm", "crm_delete_contact"))

    def test_injected_reader_controls_cron_flag(self):
        os.environ["HERMES_CRON_SESSION"] = "1"
        cg.set_session_reader(lambda k: {"HERMES_SESSION_PLATFORM": "cli"}.get(k, ""))
        self.assertEqual(cg.resolve_tier()[0], "owner")  # env cron flag ignored
        cg.set_session_reader(lambda k: {"HERMES_SESSION_PLATFORM": "cli",
                                         "HERMES_CRON_SESSION": "true"}.get(k, ""))
        self.assertEqual(cg.resolve_tier()[0], "cron")
        cg.set_session_reader(lambda k: None)
        self.assertEqual(cg.resolve_tier()[0], "unknown")

    def test_owner_from_config_file(self):
        self.session("telegram", "1001")
        self.assertEqual(cg.resolve_tier()[0], "owner")

    def test_team_reads_allowed_writes_denied_and_logged(self):
        self.session("telegram", "2002")
        self.assertIsNone(cg.check_tool_call("crm", "crm_get_contact"))
        d = cg.check_tool_call("crm", "crm_update_contact")
        self.assertEqual(d["type"], "TierDenied")
        lines = (self.home / "logs/capability-denials.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(lines[-1])["reason"], "not_in_team_whitelist")

    def test_team_whitelist_and_append(self):
        self.session("slack", "U-team")
        self.assertIsNotNone(cg.check_tool_call("crm", "crm_mark_done"))
        self.assertTrue(cg.append_to_whitelist("crm_mark_done", approver="owner"))
        self.assertFalse(cg.append_to_whitelist("crm_mark_done", approver="owner"))
        self.assertFalse(cg.append_to_whitelist("bad name # x", approver="owner"))
        self.assertIsNone(cg.check_tool_call("crm", "crm_mark_done"))
        self.assertTrue((self.home / "logs/team-whitelist-mutations.jsonl").exists())

    def test_cron_writes_blocked_reads_allowed(self):
        self.session(cron=True)
        self.assertEqual(cg.resolve_tier()[0], "cron")
        self.assertIsNone(cg.check_tool_call("crm", "crm_list_orders"))
        self.assertEqual(cg.check_tool_call("crm", "crm_create_order")["type"], "CronWriteBlocked")

    def test_live_owner_message_overrides_stale_cron_marker(self):
        self.session("telegram", "1001", msg="m1", cron=True)
        self.assertEqual(cg.resolve_tier()[0], "owner")

    def test_injected_reader_and_notifier_failure_still_denies(self):
        cg.set_session_reader(lambda k: {"HERMES_SESSION_PLATFORM": "discord", "HERMES_SESSION_USER_ID": "9"}.get(k, ""))
        def boom(event):
            raise RuntimeError("notifier down")
        cg.set_denial_notifier(boom)
        self.assertEqual(cg.check_tool_call("x", "x_send_email")["type"], "TierDenied")

    def test_missing_owner_file_means_no_owners(self):
        (self.home / "security/owner_ids.json").unlink()
        self.session("telegram", "1001")
        self.assertEqual(cg.resolve_tier()[0], "team")


if __name__ == "__main__":
    unittest.main()
