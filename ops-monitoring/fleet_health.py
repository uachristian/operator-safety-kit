#!/usr/bin/env python3
"""Fleet health check for a multi-profile agent install (ops profile).

Read-only by default. Discovers profiles, launchd agent services, cron stores,
scripts, declared endpoint monitors, and inventory drift. Designed to run from
launchd/cron without secrets in stdout: log hits are reported as fingerprints
(source, signal, exception class, HTTP code, hash), never raw log text.

Paths: fleet root = $HERMES_FLEET_ROOT, else $HERMES_HOME, else ~/.hermes.
Extra critical launchd label regexes: one per line in
<root>/profiles/ops/critical_labels.txt.
Optional tuning (JSON) at <root>/profiles/ops/fleet_health.json:
  {"noise_patterns": ["regex", ...],          # log lines counted as noise
   "skip_logs": {"<profile>": ["logs/x.log"]}} # per-profile log files to skip
launchd discovery is macOS-only; on other hosts those sections are empty.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import plistlib
import re
import socket
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

# The ops profile audits the whole fleet, so pin the fleet root explicitly:
# a profile-scoped HERMES_HOME would otherwise point at the ops sandbox.
ROOT = Path(os.getenv("HERMES_FLEET_ROOT") or os.getenv("HERMES_HOME") or str(Path.home() / ".hermes")).expanduser()
if ROOT.parent.name == "profiles":
    ROOT = ROOT.parent.parent
OPS = ROOT / "profiles" / "ops"
STATE_DIR = OPS / "state"
REPORT_DIR = OPS / "reports"
MONITORS_DIR = OPS / "monitors.d"
BASELINE = STATE_DIR / "known_inventory.json"
HERMES = ROOT / "hermes-agent" / "venv" / "bin" / "hermes"
VENV_PY = ROOT / "hermes-agent" / "venv" / "bin" / "python"
CRON_PREFLIGHT = OPS / "scripts" / "cron_preflight.py"
LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"

CRITICAL_LABEL_PATTERNS = [
    re.compile(r"^ai\.hermes\.gateway"),
    re.compile(r"webhook", re.I),
    re.compile(r"dashboard", re.I),
]
_extra_labels = OPS / "critical_labels.txt"
if _extra_labels.is_file():
    for _line in _extra_labels.read_text(errors="ignore").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#"):
            try:
                CRITICAL_LABEL_PATTERNS.append(re.compile(_line, re.I))
            except re.error:
                pass
# Generic, platform-neutral noise. Add your own via fleet_health.json.
DEFAULT_NOISE_PATTERNS = [
    r"pending_approval",
    r"network error .* reconnecting",
    r"\bBad Gateway\b",
    r"rate limited; retrying",
]
TUNING_FILE = OPS / "fleet_health.json"


def load_tuning(path: Path | None = None) -> tuple[re.Pattern[str], dict[str, set[str]]]:
    """Return (noise regex, {profile: {relative log paths to skip}})."""
    raw = read_json(path or TUNING_FILE, {})
    raw = raw if isinstance(raw, dict) else {}
    pats = list(DEFAULT_NOISE_PATTERNS)
    for p in raw.get("noise_patterns") or []:
        try:
            re.compile(str(p))
            pats.append(str(p))
        except re.error:
            continue
    skips = {str(k): {str(x) for x in (v or [])} for k, v in (raw.get("skip_logs") or {}).items()
             if isinstance(v, list)}
    return re.compile("(" + "|".join(pats) + ")", re.I), skips


ERROR_RE = re.compile(
    r"\b(ERROR|CRITICAL|Traceback|failed|FATAL|unauthorized|invalidated)\b|\b(?:HTTP|status|code)[ =:/-]*401\b|\b401 unauthorized\b",
    re.I,
)
LOG_TS_RE = re.compile(r"(?P<ts>20\d{2}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
EXCEPTION_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception))\b")
HTTP_CODE_RE = re.compile(r"\b(?:HTTP|status|code)[ =:/-]*([1-5][0-9]{2})\b", re.I)


def safe_log_example(source: str, line: str) -> str:
    """Return a diagnostic fingerprint without retaining raw untrusted log text."""
    signal_match = ERROR_RE.search(line or "")
    signal = (signal_match.group(0) if signal_match else "error").lower()
    exception_match = EXCEPTION_RE.search(line or "")
    http_match = HTTP_CODE_RE.search(line or "")
    fields = [f"source={source}", f"signal={signal}"]
    if exception_match:
        fields.append(f"exception={exception_match.group(1)}")
    if http_match:
        fields.append(f"http={http_match.group(1)}")
    fields.append(f"fingerprint={hashlib.sha256((line or '').encode('utf-8', errors='ignore')).hexdigest()[:16]}")
    return " ".join(fields)


def line_timestamp(line: str) -> float | None:
    m = LOG_TS_RE.search(line or "")
    if not m:
        return None
    raw = m.group("ts").replace(" ", "T")
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    # Normalize offsets like -0400 to -04:00 for fromisoformat.
    if len(raw) >= 5 and re.search(r"[+-]\d{4}$", raw):
        raw = raw[:-5] + raw[-5:-2] + ":" + raw[-2:]
    try:
        return datetime.fromisoformat(raw).timestamp()
    except Exception:
        return None


def run(cmd: list[str], timeout: int = 20, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, env=env)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def load_yaml_ok(path: Path) -> tuple[bool, str]:
    try:
        import yaml  # type: ignore
    except Exception:
        return True, "yaml_module_missing"
    try:
        yaml.safe_load(path.read_text())
        return True, "ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def discover_profiles() -> list[dict[str, Any]]:
    out = [{"name": "default-root", "path": str(ROOT), "cli": None, "kind": "root"}]
    pdir = ROOT / "profiles"
    if pdir.exists():
        for d in sorted(pdir.iterdir()):
            if d.is_dir():
                out.append({"name": d.name, "path": str(d), "cli": None if d.name == "default" else d.name, "kind": "profile"})
    return out


def cron_summary(profile: dict[str, Any]) -> dict[str, Any]:
    path = Path(profile["path"])
    jobs_path = path / "cron" / "jobs.json"
    result = {"present": jobs_path.exists(), "parse_ok": None, "count": 0, "loader_ok": None, "loader_count": None, "error": None}
    if not jobs_path.exists():
        return result
    try:
        raw = json.loads(jobs_path.read_text() or "[]")
        jobs = raw.get("jobs", raw) if isinstance(raw, dict) else raw
        result.update(parse_ok=True, count=len(jobs) if isinstance(jobs, list) else 0)
    except Exception as e:
        result.update(parse_ok=False, error=f"{type(e).__name__}: {e}")
        return result
    if VENV_PY.exists():
        env = os.environ.copy()
        env["HERMES_HOME"] = str(path)
        try:
            r = run([str(VENV_PY), "-c", "from cron.jobs import load_jobs; print(len(load_jobs()))"], 20, env)
            if r.returncode == 0:
                result.update(loader_ok=True, loader_count=int((r.stdout or "0").strip() or 0))
            else:
                result.update(loader_ok=False, error=(r.stderr or r.stdout).strip().split("\n")[-1][:240])
        except Exception as e:
            result.update(loader_ok=False, error=f"{type(e).__name__}: {e}")
    return result


def scripts_summary(profile: dict[str, Any], limit: int = 120) -> dict[str, Any]:
    path = Path(profile["path"])
    sdir = path / "scripts"
    py_fail: list[str] = []
    sh_fail: list[str] = []
    py_files: list[Path] = []
    sh_files: list[Path] = []
    if sdir.exists():
        files = [p for p in sdir.rglob("*") if p.is_file()]
        py_files = [p for p in files if p.suffix == ".py"]
        sh_files = [p for p in files if p.suffix in (".sh", ".bash")]
    for p in py_files[:limit]:
        try:
            ast.parse(p.read_text(errors="ignore"))
        except Exception as e:
            py_fail.append(f"{p.relative_to(path)}:{type(e).__name__}")
    for p in sh_files[:limit]:
        try:
            r = run(["bash", "-n", str(p)], 10)
            if r.returncode:
                detail = (r.stderr or r.stdout).strip().splitlines()
                sh_fail.append(f"{p.relative_to(path)}:{detail[-1] if detail else r.returncode}")
        except Exception as e:
            sh_fail.append(f"{p.relative_to(path)}:{type(e).__name__}")
    return {"py_count": len(py_files), "sh_count": len(sh_files), "py_fail": py_fail, "sh_fail": sh_fail}


def env_summary(profile: dict[str, Any]) -> dict[str, Any]:
    env = Path(profile["path"]) / ".env"
    if not env.exists():
        return {"present": False}
    keys = []
    try:
        for line in env.read_text(errors="ignore").splitlines():
            if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                keys.append(line.split("=", 1)[0].strip())
    except Exception:
        pass
    return {"present": True, "mode": oct(env.stat().st_mode & 0o777), "key_count": len(keys)}


def launchctl_inventory() -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    try:
        out = run(["launchctl", "list"], 10).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                label = parts[-1]
                # macOS registers foreground app instances as transient
                # application.<bundle>.<uid>.<asid>.<uuid> labels. They are
                # not managed Hermes LaunchAgents and the UUID changes on each
                # desktop app launch, so inventory-baselining them creates
                # constant false-positive drift.
                if label.startswith("application.com.nousresearch.hermes."):
                    continue
                if is_critical_label(label):
                    rows[label] = {"pid": None if parts[0] == "-" else parts[0], "last_status": parts[1]}
    except Exception:
        pass
    return rows


def plist_inventory() -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if not LAUNCH_AGENTS.exists():
        return rows
    for p in LAUNCH_AGENTS.glob("*.plist"):
        try:
            data = plistlib.loads(p.read_bytes())
            label = str(data.get("Label") or p.stem)
            args = data.get("ProgramArguments") or []
            program = data.get("Program") or (args[0] if args else "")
            joined = " ".join(map(str, args)) + " " + str(program)
            if "hermes" in label.lower() or ".hermes" in joined or "Hermes" in joined:
                rows[label] = {"path": str(p), "program": str(program), "args": args, "keepalive": bool(data.get("KeepAlive")), "run_at_load": bool(data.get("RunAtLoad"))}
        except Exception:
            continue
    return rows


def is_critical_label(label: str) -> bool:
    return any(p.search(label) for p in CRITICAL_LABEL_PATTERNS)


def endpoint_monitors() -> list[dict[str, Any]]:
    monitors: list[dict[str, Any]] = []
    if MONITORS_DIR.exists():
        for p in sorted(MONITORS_DIR.glob("*.json")):
            data = read_json(p, {})
            entries = data if isinstance(data, list) else data.get("monitors", []) if isinstance(data, dict) else []
            for item in entries:
                if isinstance(item, dict):
                    item = {**item, "source": str(p)}
                    monitors.append(item)
    return monitors


def check_url(url: str, timeout: int = 5, attempts: int = 1, retry_delay: float = 1.0) -> tuple[bool, str]:
    attempts = max(1, attempts)
    first_error = ""
    last_detail = ""
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HermesOpsHealth/1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(512)
                detail = f"http={resp.status} bytes>={len(body)}"
                if attempts > 1:
                    detail = f"{detail} attempt={attempt}/{attempts}"
                return 200 <= resp.status < 400, detail
        except Exception as e:
            last_detail = f"{type(e).__name__}: {e}"
            if not first_error:
                first_error = last_detail
            if attempt < attempts:
                time.sleep(max(0.0, retry_delay))
    if attempts > 1:
        return False, f"{last_detail} after {attempts} attempts; first={first_error}"
    return False, last_detail


def declared_monitor_results() -> list[dict[str, Any]]:
    out = []
    for mon in endpoint_monitors():
        kind = mon.get("type", "url")
        res = {"name": mon.get("name") or mon.get("url") or mon.get("host"), "critical": bool(mon.get("critical")), "source": mon.get("source"), "ok": None, "detail": ""}
        if kind == "url" and mon.get("url"):
            ok, detail = check_url(
                str(mon["url"]),
                int(mon.get("timeout", 5)),
                int(mon.get("attempts", 1)),
                float(mon.get("retry_delay", 1.0)),
            )
            res.update(ok=ok, detail=detail)
        elif kind == "tcp" and mon.get("host") and mon.get("port"):
            try:
                with socket.create_connection((str(mon["host"]), int(mon["port"])), timeout=int(mon.get("timeout", 5))):
                    res.update(ok=True, detail="tcp=connected")
            except Exception as e:
                res.update(ok=False, detail=f"{type(e).__name__}: {e}")
        else:
            res.update(ok=False, detail="invalid_monitor")
        out.append(res)
    return out


def log_age_bucket(seconds: float) -> str:
    minutes = max(0, int(seconds // 60))
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    return f"{hours // 24}d"


def log_findings(profile: dict[str, Any]) -> dict[str, Any]:
    path = Path(profile["path"])
    logdir = path / "logs"
    cutoff = time.time() - 24 * 3600
    findings: list[str] = []
    sources: list[str] = []
    newest_hit_mtime: float | None = None
    noisy = 0
    noise_re, skip_logs = load_tuning()
    skip = skip_logs.get(str(profile.get("name") or ""), set())
    if logdir.exists():
        files = []
        for lf in logdir.rglob("*.log"):
            try:
                files.append((lf.stat().st_mtime, lf))
            except Exception:
                pass
        for mtime, lf in sorted(files, reverse=True)[:30]:
            try:
                if lf.stat().st_mtime < cutoff:
                    continue
                text = lf.read_text(errors="ignore")[-25000:]
                hits = [ln for ln in text.splitlines() if ERROR_RE.search(ln)]
                if hits:
                    rel = str(lf.relative_to(path))
                    if rel in skip:
                        continue
                    for h in hits[-3:]:
                        hit_ts = line_timestamp(h)
                        if hit_ts is not None and hit_ts < cutoff:
                            continue
                        if noise_re.search(h):
                            noisy += 1
                        else:
                            findings.append(safe_log_example(rel, h))
                            if rel not in sources:
                                sources.append(rel)
                            newest_hit_mtime = max(newest_hit_mtime or 0, hit_ts or mtime)
            except Exception:
                pass
    newest_age = log_age_bucket(time.time() - newest_hit_mtime) if newest_hit_mtime else None
    return {"actionable_count": len(findings), "noisy_count": noisy, "examples": findings[:5], "sources": sources[:5], "newest_age": newest_age}


def cron_preflight_summary(write_report: bool = True) -> dict[str, Any]:
    if not CRON_PREFLIGHT.exists():
        return {"present": False, "ok": False, "error": f"missing {CRON_PREFLIGHT}", "summary": {}, "issues": []}
    cmd = [str(CRON_PREFLIGHT), "--json"]
    if write_report:
        cmd.insert(1, "--write-report")
        cmd.insert(2, "--propose-fixes")
    try:
        r = run(cmd, 90)
        # cron_preflight returns 1 for warnings and 2 for criticals; JSON is still valid.
        data = json.loads(r.stdout or "{}")
        data["present"] = True
        data["ok"] = r.returncode in (0, 1, 2)
        data["exit_code"] = r.returncode
        return data
    except Exception as e:
        return {"present": True, "ok": False, "error": f"{type(e).__name__}: {e}", "summary": {}, "issues": []}


def inventory_key(report: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "profiles": sorted(p["name"] for p in report["profiles"]),
        "launchd_labels": sorted(report["launchd"].keys()),
        "plists": sorted(report["plists"].keys()),
        "cron_jobs": sorted(f"{p['name']}:{j}" for p in report["profiles"] for j in p.get("cron_job_names", [])),
        "monitors": sorted(m.get("name") or "?" for m in report.get("monitors", [])),
    }


def inventory_tracks_cron_job(job: dict[str, Any]) -> bool:
    """Return whether a cron job belongs in the durable inventory baseline."""
    schedule = job.get("schedule") or {}
    repeat = job.get("repeat") or {}
    # One-shot reminders/tasks are intentionally ephemeral and should not wake
    # the fleet inventory classifier or watchdog as if they were infrastructure.
    if schedule.get("kind") == "once" or repeat.get("times") == 1:
        return False
    return True


def compute_new_inventory(current: dict[str, list[str]], baseline: dict[str, list[str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for k, vals in current.items():
        old = set(baseline.get(k, []))
        new = sorted(v for v in vals if v not in old)
        if new:
            out[k] = new
    return out


def build_report(*, write_preflight_report: bool = False) -> dict[str, Any]:
    profiles = discover_profiles()
    launchd = launchctl_inventory()
    plists = plist_inventory()
    mons = declared_monitor_results()
    preflight = cron_preflight_summary(write_report=write_preflight_report)
    profile_reports = []
    issues: list[dict[str, str]] = []
    for p in profiles:
        path = Path(p["path"])
        cfg = path / "config.yaml"
        cfg_ok = None
        cfg_detail = "missing"
        if cfg.exists():
            cfg_ok, cfg_detail = load_yaml_ok(cfg)
            if not cfg_ok:
                issues.append({"severity": "critical", "where": p["name"], "issue": f"config parse failed: {cfg_detail}"})
        env = env_summary(p)
        if env.get("present") and env.get("mode") not in ("0o600", "0o400"):
            issues.append({"severity": "warning", "where": p["name"], "issue": f".env permissions {env.get('mode')}"})
        cron = cron_summary(p)
        if cron.get("parse_ok") is False or cron.get("loader_ok") is False:
            issues.append({"severity": "critical", "where": p["name"], "issue": f"cron problem: {cron.get('error')}"})
        scripts = scripts_summary(p)
        if scripts["py_fail"] or scripts["sh_fail"]:
            issues.append({"severity": "critical", "where": p["name"], "issue": "script syntax failures"})
        logs = log_findings(p)
        if logs["actionable_count"]:
            detail = f"recent actionable log findings: {logs['actionable_count']}"
            if logs.get("newest_age"):
                detail += f"; newest={logs['newest_age']}"
            if logs.get("sources"):
                src = ", ".join(logs["sources"][:2])
                more = " …" if len(logs["sources"]) > 2 else ""
                detail += f"; sources={src}{more}"
            issues.append({"severity": "warning", "where": p["name"], "issue": detail})
        cron_names = []
        jp = path / "cron" / "jobs.json"
        if jp.exists():
            raw = read_json(jp, [])
            jobs = raw.get("jobs", raw) if isinstance(raw, dict) else raw
            if isinstance(jobs, list):
                cron_names = [
                    str(j.get("name") or j.get("job_id") or j.get("id") or "?")
                    for j in jobs
                    if isinstance(j, dict) and inventory_tracks_cron_job(j)
                ]
        profile_reports.append({**p, "config": {"present": cfg.exists(), "ok": cfg_ok, "detail": cfg_detail}, "env": env, "cron": cron, "scripts": scripts, "logs": logs, "cron_job_names": cron_names})
    for label, meta in plists.items():
        live = launchd.get(label)
        if is_critical_label(label):
            if not live:
                issues.append({"severity": "critical", "where": label, "issue": "critical launchd plist exists but job is not loaded"})
                continue
            # KeepAlive services should normally have a PID. StartInterval/RunAtLoad
            # periodic jobs are expected to be idle between ticks, so a missing PID is
            # not itself a critical outage. Preserve visibility by warning on a
            # nonzero last exit status; log scanning and dedicated monitors decide
            # whether that is actionable.
            periodic = bool(meta.get("run_at_load")) and not bool(meta.get("keepalive"))
            last_status = str(live.get("last_status"))
            if not live.get("pid") and last_status not in ("0", "-"):
                severity = "warning" if periodic else "critical"
                issues.append({"severity": severity, "where": label, "issue": f"critical launchd job idle/nonzero last_status={live.get('last_status')}"})
    for mon in mons:
        if not mon.get("ok") and mon.get("critical"):
            issues.append({"severity": "critical", "where": str(mon.get("name")), "issue": f"monitor failed: {mon.get('detail')}"})
        elif not mon.get("ok"):
            issues.append({"severity": "warning", "where": str(mon.get("name")), "issue": f"monitor failed: {mon.get('detail')}"})
    if not preflight.get("ok"):
        issues.append({"severity": "critical", "where": "cron-preflight", "issue": preflight.get("error", "preflight failed")})
    else:
        ps = preflight.get("summary", {}) or {}
        if ps.get("critical_count", 0):
            issues.append({"severity": "critical", "where": "cron-preflight", "issue": f"{ps.get('critical_count')} critical cron/script findings"})
        elif ps.get("warning_count", 0):
            issues.append({"severity": "warning", "where": "cron-preflight", "issue": f"{ps.get('warning_count')} cron/script warnings; see cron-preflight-latest.md"})
    report = {"timestamp": datetime.now().isoformat(timespec="seconds"), "profiles": profile_reports, "launchd": launchd, "plists": plists, "monitors": mons, "cron_preflight": preflight, "issues": issues}
    inv = inventory_key(report)
    baseline = read_json(BASELINE, {})
    report["inventory"] = inv
    report["new_inventory"] = compute_new_inventory(inv, baseline) if baseline else {}
    crit = [i for i in issues if i["severity"] == "critical"]
    warn = [i for i in issues if i["severity"] == "warning"]
    report["fleet_status"] = "red" if crit else "yellow" if warn or report["new_inventory"] else "green"
    return report


def render_markdown(report: dict[str, Any], critical_only: bool = False) -> str:
    crit = [i for i in report["issues"] if i["severity"] == "critical"]
    warn = [i for i in report["issues"] if i["severity"] == "warning"]
    new = report.get("new_inventory", {})
    if critical_only and not crit and not new:
        return ""
    lines = [f"## Hermes Ops Fleet Health — {report['fleet_status'].upper()}", f"Time: {report['timestamp']}", ""]
    if crit:
        lines.append("Critical:")
        for i in crit[:12]:
            lines.append(f"- {i['where']}: {i['issue']}")
        lines.append("")
    if new:
        lines.append("NEW_INVENTORY needing classification:")
        for k, vals in new.items():
            lines.append(f"- {k}: {', '.join(vals[:12])}{' …' if len(vals) > 12 else ''}")
        lines.append("")
    if not critical_only:
        lines.append("Summary:")
        lines.append(f"- profiles: {len(report['profiles'])}")
        lines.append(f"- launchd Hermes jobs loaded: {len(report['launchd'])}")
        lines.append(f"- Hermes launchd plists discovered: {len(report['plists'])}")
        lines.append(f"- declared monitors checked: {len(report['monitors'])}")
        pf = report.get("cron_preflight", {}).get("summary", {}) or {}
        if pf:
            lines.append(f"- cron preflight: {pf.get('enabled_script_jobs', 0)} enabled script jobs, {pf.get('critical_count', 0)} critical, {pf.get('warning_count', 0)} warnings")
        lines.append(f"- warnings: {len(warn)}")
        lines.append("")
        if warn:
            lines.append("Warnings:")
            for i in warn[:12]:
                lines.append(f"- {i['where']}: {i['issue']}")
            lines.append("")
        lines.append("Profile cron counts:")
        for p in report["profiles"]:
            c = p["cron"]
            if c.get("present"):
                lines.append(f"- {p['name']}: {c.get('count')} jobs, loader={c.get('loader_ok')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--critical-only", action="store_true")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--write-report", action="store_true")
    args = ap.parse_args()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    MONITORS_DIR.mkdir(parents=True, exist_ok=True)
    report = build_report(write_preflight_report=args.write_report)
    if args.update_baseline:
        BASELINE.write_text(json.dumps(report["inventory"], indent=2, sort_keys=True) + "\n")
    if args.write_report:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        (REPORT_DIR / f"fleet-health-{stamp}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (REPORT_DIR / "latest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (REPORT_DIR / "latest.md").write_text(render_markdown(report))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        text = render_markdown(report, critical_only=args.critical_only)
        if text:
            print(text, end="")
    # This script is used by no_agent cron jobs. In Hermes no_agent mode,
    # non-zero means the script itself failed and the scheduler wraps stdout in
    # a scary "Cron failed" error. Fleet health findings are already expressed
    # by stdout/report status, so successful report generation must exit 0.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
