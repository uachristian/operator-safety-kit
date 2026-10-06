"""
capability_gate.py — Tier check for agent tool calls (MCP or native).

Call check_tool_call(server, tool) at the top of every tool dispatch, BEFORE the
call reaches the tool. It resolves who is driving the current turn and decides:

  owner — explicitly local session (platform in LOCAL_PLATFORMS, e.g. "cli")
          or a platform user whose ID is in the owner list. Everything allowed.
  cron  — autonomous scheduled run. Reads allowed; writes blocked and logged as
          dry-run proposals for a human to approve.
  team  — any other identified platform user. Reads allowed; writes only if on
          the team write whitelist.
  unknown — missing/empty session context. Reads allowed; ALL writes denied.
          Missing context never grants owner (fail closed).

Write detection FAILS CLOSED: a tool is a READ only if its normalized name
(camelCase / hyphens / dots -> snake_case, lowercased, optional "mcp_" and
server-name prefix stripped) is an exact READ_TOOL_NAMES entry or starts with a
READ_TOOL_PREFIXES verb, and contains no WRITE_VERB_TOKENS. Everything else,
including unknown names, is a WRITE.

CONFIGURATION (no identities are hardcoded)
-------------------------------------------
Owner IDs: JSON file {"telegram": ["<id>"], "slack": ["<id>"]} at
  $HERMES_HOME/security/owner_ids.json, or set_owner_ids({...}).
Team write whitelist: one tool name per line ('#' comments) at
  $HERMES_HOME/security/team_write_whitelist.txt, reloaded every call.
Read allowlist extension: $HERMES_HOME/security/read_tool_allowlist.txt, one
  entry per line ('#' comments): an exact tool name, or "prefix:<verb>_".
  Entries extend the built-in allowlist; they cannot remove from it.
Session context is read from env (or an injected reader via set_session_reader;
when a reader is injected, ALL keys including the cron flag come from it):
  HERMES_SESSION_PLATFORM, HERMES_SESSION_USER_ID, HERMES_SESSION_MESSAGE_ID,
  HERMES_CRON_SESSION=1.
Denials append to $HERMES_HOME/logs/capability-denials.jsonl.
An optional notifier callback (set_denial_notifier) can page the owner; route
its text through output_gate.check_message before sending.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

READ_TOOL_PREFIXES: tuple[str, ...] = (
    "get_", "list_", "search_", "read_", "find_", "view_", "show_", "describe_", "lookup_",
)
READ_TOOL_NAMES: frozenset[str] = frozenset({
    "read_file", "search_files", "web_search", "web_extract", "session_search",
    "skill_view", "skills_list",
})
# A read-looking name that also carries one of these tokens is treated as a write
# (e.g. "get_and_delete_item"). Over-blocking here is the safe direction.
WRITE_VERB_TOKENS: frozenset[str] = frozenset({
    "create", "add", "update", "upsert", "delete", "remove", "set", "move", "mark",
    "assign", "bulk", "send", "post", "put", "patch", "write", "archive", "unarchive",
    "attach", "detach", "pay", "refund", "charge", "approve", "transfer", "deploy",
    "execute", "exec", "run", "terminal", "edit", "modify", "insert", "drop", "kill",
    "submit", "publish", "purge", "reset", "revoke", "grant", "cancel", "merge", "push",
    "replace", "rename", "upload", "save", "store", "commit", "sync", "install", "restart",
    "clear", "rotate", "invoke", "call", "trigger", "destroy", "rm", "append", "import",
    "unlock", "lock", "enable", "disable", "start", "stop", "schedule", "apply", "restore",
    "and", "or", "then",
})
LOCAL_PLATFORMS: frozenset[str] = frozenset({"cli", "local", "desktop"})

BASE_TEAM_WRITE_WHITELIST: set[str] = set()

_owner_ids_override: Optional[dict[str, set[str]]] = None
_session_reader: Optional[Callable[[str], str]] = None
_denial_notifier: Optional[Callable[[dict], None]] = None


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()


def owner_ids_path() -> Path:
    return _hermes_home() / "security" / "owner_ids.json"


def whitelist_path() -> Path:
    return _hermes_home() / "security" / "team_write_whitelist.txt"


def read_allowlist_path() -> Path:
    return _hermes_home() / "security" / "read_tool_allowlist.txt"


def denial_log_path() -> Path:
    return _hermes_home() / "logs" / "capability-denials.jsonl"


def whitelist_audit_path() -> Path:
    return _hermes_home() / "logs" / "team-whitelist-mutations.jsonl"


def set_owner_ids(mapping: Optional[dict[str, Any]]) -> None:
    global _owner_ids_override
    _owner_ids_override = None if mapping is None else {k.lower(): {str(x) for x in v} for k, v in mapping.items()}


def set_session_reader(fn: Optional[Callable[[str], str]]) -> None:
    """Inject a per-turn context reader (e.g. contextvars-backed) instead of os.environ."""
    global _session_reader
    _session_reader = fn


def set_denial_notifier(fn: Optional[Callable[[dict], None]]) -> None:
    global _denial_notifier
    _denial_notifier = fn


def load_owner_ids() -> dict[str, set[str]]:
    if _owner_ids_override is not None:
        return _owner_ids_override
    try:
        raw = json.loads(owner_ids_path().read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k).lower(): {str(x) for x in (v or [])} for k, v in raw.items()}


def _read(name: str) -> str:
    if _session_reader is not None:
        return _session_reader(name) or ""
    return os.environ.get(name, "") or ""


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_tier() -> tuple[str, str, str]:
    """Return (tier, platform, user_id). Missing context never yields owner."""
    platform = _read("HERMES_SESSION_PLATFORM").strip().lower()
    user_id = _read("HERMES_SESSION_USER_ID").strip()
    message_id = _read("HERMES_SESSION_MESSAGE_ID").strip()
    cron = _truthy(_read("HERMES_CRON_SESSION"))
    owners = load_owner_ids().get(platform, set()) if platform else set()

    # A live owner message beats a stale process-level cron marker.
    if platform and user_id and message_id and user_id in owners:
        return ("owner", platform, user_id)
    if cron:
        return ("cron", platform or "cron", user_id)
    if platform in LOCAL_PLATFORMS:
        return ("owner", platform, user_id)
    if platform and user_id and user_id in owners:
        return ("owner", platform, user_id)
    if not platform or not user_id:
        return ("unknown", platform or "unknown", user_id)
    return ("team", platform, user_id)


def normalize_tool_name(name: str) -> str:
    """camelCase / PascalCase / hyphens / dots / spaces -> lowercase snake_case."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", str(name or "").strip())
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    return re.sub(r"_+", "_", s)


def load_read_allowlist() -> tuple[frozenset[str], tuple[str, ...]]:
    """Built-in read names/prefixes plus the optional extension file."""
    names, prefixes = set(READ_TOOL_NAMES), list(READ_TOOL_PREFIXES)
    try:
        lines = read_allowlist_path().read_text().splitlines()
    except OSError:
        lines = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.lower().startswith("prefix:"):
            pre = normalize_tool_name(line[7:])
            if pre:
                prefixes.append(pre + "_")
        else:
            n = normalize_tool_name(line)
            if n:
                names.add(n)
    return frozenset(names), tuple(prefixes)


def _candidates(norm: str, server_name: str) -> list[str]:
    out = [norm]
    if norm.startswith("mcp_"):
        out.append(norm[4:])
    server = normalize_tool_name(server_name)
    for c in list(out):
        if server and c.startswith(server + "_"):
            out.append(c[len(server) + 1:])
    return [c for c in out if c]


def is_write_tool(tool_name: str, server_name: str = "") -> bool:
    """Fail closed: True unless the name is on the explicit read allowlist."""
    norm = normalize_tool_name(tool_name)
    if not norm:
        return True
    names, prefixes = load_read_allowlist()
    for cand in _candidates(norm, server_name):
        if cand in names:
            return False
        if cand.startswith(prefixes) and not (set(cand.split("_")) & WRITE_VERB_TOKENS):
            return False
    return True


def load_team_write_whitelist() -> set[str]:
    wl = set(BASE_TEAM_WRITE_WHITELIST)
    try:
        for line in whitelist_path().read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                wl.add(line)
    except OSError:
        pass
    return wl


def _append_jsonl(path: Path, event: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass


def append_to_whitelist(tool_name: str, approver: str, source: str = "owner_approval") -> bool:
    """Owner-approved whitelist growth with an audit trail. Returns True if added."""
    tool_name = tool_name.strip()
    if not tool_name or any(c.isspace() or c == "#" for c in tool_name):
        return False
    now = datetime.now(timezone.utc)
    if tool_name in load_team_write_whitelist():
        _append_jsonl(whitelist_audit_path(), {"ts": now.isoformat(), "tool": tool_name,
                                               "approver": approver, "source": source, "action": "already_present"})
        return False
    p = whitelist_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with p.open("a") as f:
        f.write(f"{tool_name}    # added {now:%Y-%m-%d} via {source}\n")
    _append_jsonl(whitelist_audit_path(), {"ts": now.isoformat(), "tool": tool_name,
                                           "approver": approver, "source": source, "action": "added"})
    return True


def _deny(kind: str, server: str, tool: str, tier: str, platform: str, user_id: str, reason: str, msg: str) -> dict:
    event = {"ts": datetime.now(timezone.utc).isoformat(), "server": server, "tool": tool,
             "platform": platform, "user_id": user_id, "tier": tier, "reason": reason}
    _append_jsonl(denial_log_path(), event)
    if _denial_notifier is not None:
        try:
            _denial_notifier(event)
        except Exception:  # a notifier failure must never turn a deny into an allow
            pass
    return {"ok": False, "type": kind, "tier": tier, "platform": platform, "tool": tool, "message": msg}


def check_tool_call(server_name: str, tool_name: str) -> Optional[dict[str, Any]]:
    """None -> allow. A dict -> deny (return it to the model as a structured error)."""
    tier, platform, user_id = resolve_tier()
    if tier == "owner" or not is_write_tool(tool_name, server_name):
        return None
    if tier == "cron":
        return _deny("CronWriteBlocked", server_name, tool_name, tier, platform, user_id,
                     "cron_write_blocked",
                     f"Tool '{tool_name}' is a write and cannot run from an autonomous session. "
                     f"The proposal was logged; an owner must approve it interactively.")
    if tier == "team" and tool_name in load_team_write_whitelist():
        return None
    reason = "not_in_team_whitelist" if tier == "team" else "unknown_session_context"
    return _deny("TierDenied", server_name, tool_name, tier, platform, user_id, reason,
                 f"Tool '{tool_name}' is not authorized for tier:{tier} on '{platform}'. "
                 f"Ask the owner to approve it.")
