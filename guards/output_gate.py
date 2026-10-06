"""
output_gate.py — Validate outbound agent messages before they leave.

Second line of defense. wrap_untrusted reduces prompt-injection success at the
input boundary; output_gate catches what got through by inspecting WHAT the
agent is about to send, WHERE, and HOW OFTEN.

USAGE
-----
    from guards.output_gate import check_message

    verdict = check_message(text=draft, destination="telegram", agent="assistant")
    if not verdict.allowed:
        log.warning("outbound blocked: %s", verdict.reasons)
        return
    send(draft)

MODES
-----
- "log_only" (default): soft checks log/warn but allow. Use during rollout.
- "enforce": soft checks block too.
- Any unknown mode string fails CLOSED to enforce.
Set with OUTPUT_GATE_MODE env var or mode= per call.

CHECKS
------
Hard block in BOTH modes:
  1. Secret-shaped strings (API keys, bot tokens, private keys, key=value secrets)
  2. Suspicious URLs: any IP-literal host (IPv4 in dotted, decimal, hex, octal
     or short form; IPv6 incl. bracketed), URL shorteners, punycode/IDN
     homographs (punycode or raw non-ASCII hosts)
Soft block (enforce mode only; warnings in log_only):
  2b. URLs whose host cannot be parsed
Soft block (enforce mode only; warnings in log_only):
  3. Length cap per destination type
  4. Domains not on the allowlist
  5. Per-agent rate limit

FILES
-----
Domain allowlist: domain_allowlist.txt next to this file, else
domain_allowlist.sample.txt; override with set_allowlist_file(path).
State + audit go under $HERMES_HOME (default ~/.hermes):
  security/state/rate_limits.json, logs/output-gate.jsonl
The audit log stores a SHA-256 of the text, never the text itself.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union
from urllib.parse import urlparse

try:
    import fcntl  # POSIX only
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

_HERE = Path(__file__).parent
_ALLOWLIST_OVERRIDE: Optional[Path] = None

MODE_LOG_ONLY = "log_only"
MODE_ENFORCE = "enforce"

MAX_MESSAGE_LENGTH = {
    "slack": 4000,
    "telegram": 4000,
    "discord": 2000,
    "sms": 1600,
    "imessage": 4000,
    "email": 50000,
    "record": 5000,   # notes written into a CRM / ticket / work-order system
    "generic": 4000,
}

# (max actions, window seconds) per agent bucket.
RATE_LIMITS = {
    "default": (50, 3600),
}

SECRET_PATTERNS = [
    (r"sk-ant-[a-zA-Z0-9_\-]{20,}", "anthropic_api_key"),
    (r"sk-[a-zA-Z0-9_\-]{20,}", "openai_style_api_key"),
    (r"xox[baprs]-[a-zA-Z0-9\-]{10,}", "slack_token"),
    (r"\b\d{8,10}:[a-zA-Z0-9_\-]{30,}", "telegram_bot_token"),
    (r"gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}", "github_token"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"AIza[0-9A-Za-z_\-]{35}", "google_api_key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private_key"),
    (r"(?:api[_-]?key|secret|password|token)[\"'\s:=]+[a-zA-Z0-9_\-]{24,}", "generic_secret_assignment"),
]
_SECRET_RX = [(re.compile(p, re.I), label) for p, label in SECRET_PATTERNS]

_SHORTENER_HOSTS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "short.link", "tiny.cc", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "x.co", "t2m.io",
})
# Scheme-anywhere, so "hxxp", "ftp", "javascript:" style tricks still get a host check.
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s<>\"'`)]+", re.I)
_HOST_OK_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$")


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()


def rate_limit_state_path() -> Path:
    return _hermes_home() / "security" / "state" / "rate_limits.json"


def audit_log_path() -> Path:
    return _hermes_home() / "logs" / "output-gate.jsonl"


def get_current_mode() -> str:
    return os.environ.get("OUTPUT_GATE_MODE", MODE_LOG_ONLY)


# ---- allowlist ----

_cached_allowlist: Optional[set[str]] = None


def set_allowlist_file(path: Optional[Union[str, Path]]) -> None:
    global _ALLOWLIST_OVERRIDE
    _ALLOWLIST_OVERRIDE = Path(path) if path else None
    reload_allowlist()


def _allowlist_file() -> Optional[Path]:
    if _ALLOWLIST_OVERRIDE is not None:
        return _ALLOWLIST_OVERRIDE
    for name in ("domain_allowlist.txt", "domain_allowlist.sample.txt"):
        if (_HERE / name).exists():
            return _HERE / name
    return None


def _allowlist() -> set[str]:
    global _cached_allowlist
    if _cached_allowlist is None:
        path = _allowlist_file()
        domains: set[str] = set()
        if path and path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
        _cached_allowlist = domains
    return _cached_allowlist


def reload_allowlist() -> None:
    global _cached_allowlist
    _cached_allowlist = None


@dataclass
class OutputGateResult:
    allowed: bool
    mode: str
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    secrets_found: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)
    novel_domains: list[str] = field(default_factory=list)
    rate_limit_exceeded: bool = False

    def __bool__(self) -> bool:
        return self.allowed


def _scan_secrets(text: str) -> list[str]:
    return [label for rx, label in _SECRET_RX if rx.search(text)]


def _parse_ipv4_part(part: str) -> Optional[int]:
    """inet_aton-style number: 0x.. hex, leading-0 octal, else decimal."""
    p = part.lower()
    try:
        if p.startswith("0x"):
            return int(p[2:] or "0", 16)
        if len(p) > 1 and p.startswith("0"):
            return int(p[1:], 8)
        return int(p, 10) if p.isdigit() else None
    except ValueError:
        return None


def _legacy_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """Parse every form inet_aton accepts: a, a.b, a.b.c, a.b.c.d in any radix."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or any(not x for x in parts):
        return None
    nums = [_parse_ipv4_part(x) for x in parts]
    if any(n is None for n in nums):
        return None
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (5 - len(parts)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (5 - len(parts)) + last
    return ipaddress.IPv4Address(value)


def _ip_literal(host: str) -> Optional[str]:
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h.split("%", 1)[0]))
    except ValueError:
        pass
    ip = _legacy_ipv4(h.rstrip("."))
    return str(ip) if ip is not None else None


def _url_hosts(text: str) -> list[tuple[str, Optional[str]]]:
    """[(raw_url, host_or_None)]. None means the URL could not be parsed safely."""
    out: list[tuple[str, Optional[str]]] = []
    for m in _URL_RE.finditer(text):
        raw = m.group(0).rstrip(".,;:!?")
        try:
            parsed = urlparse(raw)
            host = parsed.hostname
            parsed.port  # raises ValueError on a malformed port
        except ValueError:
            out.append((raw, None))
            continue
        out.append((raw, host.lower() if host else None))
    return out


def _extract_hosts(text: str) -> list[str]:
    hosts = []
    for _raw, h in _url_hosts(text):
        if h and _ip_literal(h) is None:
            hosts.append(h.strip("."))
    return hosts


def _classify_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return "unparseable_url"
    if _ip_literal(host) is not None:
        return "raw_ip_url"
    h = host.strip(".")
    if h and not h.isascii():
        return "non_ascii_host"  # raw IDN: homograph risk, same as punycode
    if not h or not _HOST_OK_RE.match(h):
        return "unparseable_url"
    if re.fullmatch(r"(0x[0-9a-f]*|[0-9]+)", h.rsplit(".", 1)[-1]):
        return "unparseable_url"  # numeric last label: browsers treat it as IPv4
    if h in _SHORTENER_HOSTS:
        return "url_shortener"
    if any(part.startswith("xn--") for part in h.split(".")):
        return "punycode_domain"
    return None


SOFT_URL_LABELS = frozenset({"unparseable_url"})  # block in enforce, warn in log_only


def _scan_suspicious_urls(text: str) -> list[str]:
    found: list[str] = []
    for _raw, host in _url_hosts(text):
        label = _classify_host(host)
        if label and label not in found:
            found.append(label)
    return found


def _domain_allowed(domain: str, allow: set[str]) -> bool:
    parts = domain.lower().strip(".").split(".")
    return any(".".join(parts[i:]) in allow for i in range(len(parts) - 1)) or domain in allow


def _write_json_atomic(path: Path, data: object) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _check_rate_limit(agent: str) -> tuple[bool, dict]:
    """Lock-safe sliding-window counter. Fails OPEN on filesystem errors
    (availability over strictness); the hard checks never depend on it."""
    cap, window = RATE_LIMITS.get(agent, RATE_LIMITS["default"])
    now = time.time()
    path = rate_limit_state_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = path.with_name(f".{path.name}.lock")
        with lock.open("a+") as lf:
            if fcntl:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                try:
                    state = json.loads(path.read_text()) if path.exists() else {}
                except (OSError, ValueError):
                    state = {}
                ts = [t for t in state.get(agent, {}).get("timestamps", [])
                      if isinstance(t, (int, float)) and t > now - window]
                within = len(ts) < cap
                ts.append(now)
                state[agent] = {"timestamps": ts}
                _write_json_atomic(path, state)
            finally:
                if fcntl:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except OSError:
        return True, {"current_count": 0, "cap": cap, "window_s": window, "state_persisted": False}
    return within, {"current_count": len(ts), "cap": cap, "window_s": window, "state_persisted": True}


def _audit(event: dict) -> None:
    try:
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except OSError:
        pass  # auditing is best-effort; the verdict is already decided


def _destination_class(destination: str) -> str:
    raw = str(destination or "generic").split(":", 1)[0].lower()
    return re.sub(r"[^a-z0-9_-]", "", raw)[:32] or "generic"


def _soft(result: OutputGateResult, mode: str, reason: str) -> None:
    if mode == MODE_ENFORCE:
        result.reasons.append(reason)
        result.allowed = False
    else:
        result.warnings.append(reason)


def check_message(
    text: object,
    destination: str = "generic",
    agent: str = "default",
    mode: Optional[str] = None,
    skip_rate_limit: bool = False,
) -> OutputGateResult:
    """Check one outbound message. In log_only mode `.allowed` is False only for
    hard blocks; everything else lands in `.warnings`."""
    mode = (mode or get_current_mode() or MODE_LOG_ONLY).strip().lower()
    if mode not in (MODE_LOG_ONLY, MODE_ENFORCE):
        mode = MODE_ENFORCE  # a typo must not silently disable enforcement
    text = "" if text is None else str(text)
    result = OutputGateResult(allowed=True, mode=mode)

    secrets = _scan_secrets(text)
    if secrets:
        result.secrets_found = secrets
        result.reasons.append(f"secret_detected:{','.join(secrets)}")
        result.allowed = False

    sus = _scan_suspicious_urls(text)
    if sus:
        result.suspicious_urls = sus
        hard = [x for x in sus if x not in SOFT_URL_LABELS]
        soft = [x for x in sus if x in SOFT_URL_LABELS]
        if hard:
            result.reasons.append(f"suspicious_url:{','.join(hard)}")
            result.allowed = False
        if soft:
            _soft(result, mode, f"suspicious_url:{','.join(soft)}")

    dest = _destination_class(destination)
    cap = MAX_MESSAGE_LENGTH.get(dest, MAX_MESSAGE_LENGTH["generic"])
    if len(text) > cap:
        _soft(result, mode, f"length_exceeded:{len(text)}>{cap}")

    allow = _allowlist()
    novel = [d for d in _extract_hosts(text) if not _domain_allowed(d, allow)]
    if novel:
        result.novel_domains = novel
        _soft(result, mode, f"novel_domains:{','.join(novel)}")

    if not skip_rate_limit:
        within, rl = _check_rate_limit(agent)
        if not within:
            result.rate_limit_exceeded = True
            _soft(result, mode, f"rate_limit:{rl['current_count']}>{rl['cap']}/{rl['window_s']}s")

    _audit({
        "ts": time.time(),
        "agent": agent,
        "destination_class": dest,
        "mode": mode,
        "allowed": result.allowed,
        "reasons": [r.split(":", 1)[0] for r in result.reasons],
        "warnings": [w.split(":", 1)[0] for w in result.warnings],
        "text_length": len(text),
        "text_sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
    })
    return result


def check_record_write(tool: str, payload: dict, agent: str = "default",
                       mode: Optional[str] = None) -> OutputGateResult:
    """Variant for structured writes (CRM notes, tickets): scans the JSON form."""
    return check_message(json.dumps(payload, default=str), destination="record", agent=agent, mode=mode)


if __name__ == "__main__":
    import sys
    v = check_message(sys.stdin.read(), destination=(sys.argv[1] if len(sys.argv) > 1 else "generic"),
                      skip_rate_limit=True)
    print(json.dumps({"allowed": v.allowed, "mode": v.mode, "reasons": v.reasons, "warnings": v.warnings}))
    sys.exit(0 if v.allowed else 1)
