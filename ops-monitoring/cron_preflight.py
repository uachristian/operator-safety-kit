#!/usr/bin/env python3
"""Cron/script preflight for a multi-profile agent install (ops profile).

Read-only scanner. It does not run cron jobs, mutate cron records, or create
wrappers. It verifies that every enabled script-based cron resolves to an
existing script in the location Hermes will use for that job/profile and emits
human-readable fix proposals for approval.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(os.getenv("HERMES_FLEET_ROOT") or os.getenv("HERMES_HOME") or str(Path.home() / ".hermes")).expanduser()
if ROOT.parent.name == "profiles":
    ROOT = ROOT.parent.parent
OPS = ROOT / "profiles" / "ops"
REPORT_DIR = OPS / "reports"
ROOT_SCRIPTS = ROOT / "scripts"
PROFILES = ROOT / "profiles"

SCRIPT_NOT_FOUND_RE = re.compile(r"Script not found:\s*(?P<path>\S.*)$", re.I)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(errors="replace") or "null")
    except Exception:
        return default


def run(cmd: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def cron_stores() -> list[dict[str, Any]]:
    stores = [{"store": "default", "profile": None, "home": ROOT, "jobs_path": ROOT / "cron" / "jobs.json"}]
    if PROFILES.exists():
        for p in sorted(PROFILES.iterdir()):
            if p.is_dir():
                stores.append({"store": p.name, "profile": p.name, "home": p, "jobs_path": p / "cron" / "jobs.json"})
    return stores


def normalize_jobs(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        raw = raw.get("jobs", raw)
    if isinstance(raw, dict):
        raw = list(raw.values())
    if not isinstance(raw, list):
        return []
    return [j for j in raw if isinstance(j, dict)]


def job_id(job: dict[str, Any]) -> str:
    return str(job.get("id") or job.get("job_id") or job.get("name") or "<unnamed>")


def job_name(job: dict[str, Any]) -> str:
    # Never fall back to prompt text: prompts can hold private instructions.
    return str(job.get("name") or job.get("id") or job.get("job_id") or "<unnamed>")[:120]


def job_enabled(job: dict[str, Any]) -> bool:
    if job.get("paused") or job.get("disabled"):
        return False
    if job.get("enabled") is False:
        return False
    return True


def effective_profile(store_profile: str | None, job: dict[str, Any]) -> str | None:
    # Profile stored on the job wins; otherwise profile-local cron stores imply that profile.
    return job.get("profile") or store_profile


def parse_dt(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", text):
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]
    try:
        dt = datetime.fromisoformat(text)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def first_run_pending(job: dict[str, Any]) -> bool:
    if job.get("last_run_at") or job.get("last_status") not in (None, "", "null"):
        return False
    next_dt = parse_dt(job.get("next_run_at"))
    return bool(next_dt and next_dt > datetime.now(timezone.utc))


def resolve_script(script: str, profile: str | None) -> tuple[Path, Path | None, str]:
    sp = Path(script).expanduser()
    if sp.is_absolute():
        return sp, None, "absolute"
    if profile:
        return ROOT / "profiles" / profile / "scripts" / script, ROOT_SCRIPTS / script, "profile-relative"
    return ROOT_SCRIPTS / script, None, "root-relative"


def syntax_check(path: Path) -> tuple[bool, str]:
    suffix = path.suffix.lower()
    try:
        if suffix == ".py":
            ast.parse(path.read_text(errors="ignore"))
            return True, "python_ast_ok"
        if suffix in (".sh", ".bash") or path.name.endswith(".sh"):
            r = run(["bash", "-n", str(path)], 20)
            if r.returncode == 0:
                return True, "bash_n_ok"
            detail = (r.stderr or r.stdout or f"exit={r.returncode}").strip().splitlines()
            return False, detail[-1][:240] if detail else f"exit={r.returncode}"
        return True, "not_checked"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def recent_script_not_found(job: dict[str, Any]) -> str | None:
    blobs = [job.get("last_error"), job.get("error"), job.get("last_stderr"), job.get("last_output")]
    for blob in blobs:
        if not blob:
            continue
        m = SCRIPT_NOT_FOUND_RE.search(str(blob))
        if m:
            return m.group("path").strip()
    return None


def issue(severity: str, code: str, job: dict[str, Any], store: str, profile: str | None, script: str, resolved: Path, detail: str, proposal: str) -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "store": store,
        "job_id": job_id(job),
        "job_name": job_name(job),
        "profile": profile,
        "script": script,
        "resolved_path": str(resolved),
        "detail": detail,
        "proposal": proposal,
    }


def scan() -> dict[str, Any]:
    stores_out: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    first_pending: list[dict[str, Any]] = []
    script_jobs = 0
    enabled_script_jobs = 0
    checked_paths: set[str] = set()

    for s in cron_stores():
        jobs_path: Path = s["jobs_path"]
        store = s["store"]
        store_profile = s["profile"]
        if not jobs_path.exists():
            stores_out.append({"store": store, "jobs_path": str(jobs_path), "present": False, "count": 0})
            continue
        raw = read_json(jobs_path, [])
        jobs = normalize_jobs(raw)
        stores_out.append({"store": store, "jobs_path": str(jobs_path), "present": True, "count": len(jobs)})
        for job in jobs:
            script = job.get("script")
            if not script:
                continue
            script_jobs += 1
            enabled = job_enabled(job)
            if enabled:
                enabled_script_jobs += 1
                if first_run_pending(job):
                    first_pending.append({
                        "store": store,
                        "profile": effective_profile(store_profile, job) or "default",
                        "job_id": job_id(job),
                        "job_name": job_name(job),
                        "next_run_at": job.get("next_run_at"),
                    })
            profile = effective_profile(store_profile, job)
            resolved, alternate, mode = resolve_script(str(script), profile)
            checked_paths.add(str(resolved))
            if alternate:
                checked_paths.add(str(alternate))
            snf = recent_script_not_found(job)
            # Treat a prior "Script not found" metadata entry as stale once the
            # exact path reported by the scheduler exists again. The normal
            # existence/executable/syntax checks below still validate the
            # currently resolved script path.
            if snf and Path(snf).exists():
                snf = None
            if snf:
                issues.append(issue(
                    "critical" if enabled else "warning",
                    "recent_script_not_found",
                    job, store, profile, str(script), Path(snf),
                    "job metadata contains recent Script not found error",
                    f"Verify the resolved path and create/restore a wrapper only after approval: {snf}",
                ))
            if not resolved.exists():
                alt_detail = f"; alternate root exists={alternate.exists()} at {alternate}" if alternate else ""
                proposal = ""
                if alternate and alternate.exists() and profile:
                    if str(script).endswith((".sh", ".bash")):
                        proposal = f"Create profile-local shell wrapper {resolved} that execs {alternate}."
                    elif str(script).endswith(".py"):
                        proposal = f"Create profile-local Python wrapper {resolved} that runpy.run_path()s {alternate}."
                    else:
                        proposal = f"Create profile-local compatibility wrapper {resolved} for canonical root script {alternate}."
                else:
                    proposal = f"Restore script at {resolved} or update cron {job_id(job)} to the approved canonical path."
                issues.append(issue(
                    "critical" if enabled else "warning",
                    "missing_resolved_script",
                    job, store, profile, str(script), resolved,
                    f"resolved script does not exist ({mode}){alt_detail}",
                    proposal,
                ))
                continue
            if enabled and resolved.suffix in (".sh", ".bash") and not os.access(resolved, os.X_OK):
                issues.append(issue(
                    "critical",
                    "script_not_executable",
                    job, store, profile, str(script), resolved,
                    "shell script exists but is not executable",
                    f"chmod 755 {resolved}",
                ))
            ok, detail = syntax_check(resolved)
            if not ok:
                issues.append(issue(
                    "critical" if enabled else "warning",
                    "script_syntax_failed",
                    job, store, profile, str(script), resolved,
                    detail,
                    f"Patch syntax error in {resolved} after backing it up.",
                ))
            # Guard against central profile-override jobs whose profile-local script
            # exists but the default scheduler may resolve the same relative name
            # under <fleet root>/scripts during no-agent/script execution.
            if store == "default" and profile and alternate and resolved.exists() and not alternate.exists():
                issues.append(issue(
                    "critical" if enabled else "warning",
                    "missing_root_compatibility_wrapper",
                    job, store, profile, str(script), alternate,
                    f"central profile job has profile-local script at {resolved} but no root compatibility wrapper",
                    f"Create root wrapper {alternate} that delegates to {resolved}.",
                ))
            # Advisory: profile job has both root and profile scripts. This is OK, but worth visibility.
            if profile and alternate and alternate.exists() and resolved.exists():
                # Only warn for non-trivial divergence: profile script is not a tiny wrapper or differs from root.
                try:
                    prof_text = resolved.read_text(errors="ignore")[:2000]
                    alt_text = alternate.read_text(errors="ignore")[:2000]
                    # Accept either direction as an intentional compatibility wrapper:
                    # profile -> root (older repair pattern) or root -> profile (canonical
                    # profile-local script with root shim for manual invocations).
                    profile_home_ref = str(resolved).replace(str(Path.home()), "$HOME")
                    profile_tilde_ref = str(resolved).replace(str(Path.home()), "~")
                    root_home_ref = str(alternate).replace(str(Path.home()), "$HOME")
                    root_tilde_ref = str(alternate).replace(str(Path.home()), "~")
                    wrapper_markers = ("Compatibility wrapper", "Compatibility cron wrapper", "run_path(")
                    prof_wraps_root = (
                        str(alternate) in prof_text
                        or root_home_ref in prof_text
                        or root_tilde_ref in prof_text
                        or any(marker in prof_text for marker in wrapper_markers)
                    )
                    root_wraps_profile = (
                        str(resolved) in alt_text
                        or profile_home_ref in alt_text
                        or profile_tilde_ref in alt_text
                        or any(marker in alt_text for marker in wrapper_markers)
                    )
                    looks_wrapper = prof_wraps_root or root_wraps_profile
                    if not looks_wrapper and prof_text != alt_text:
                        issues.append(issue(
                            "advisory",
                            "profile_script_differs_from_root",
                            job, store, profile, str(script), resolved,
                            f"profile script and root script both exist but do not look like a wrapper; root={alternate}",
                            f"Review whether {resolved} is intentionally profile-specific or should delegate to {alternate}.",
                        ))
                except Exception:
                    pass

    crit = [i for i in issues if i["severity"] == "critical"]
    warn = [i for i in issues if i["severity"] == "warning"]
    advisory = [i for i in issues if i["severity"] == "advisory"]
    status = "red" if crit else "yellow" if warn else "green"
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "status": status,
        "stores": stores_out,
        "summary": {
            "cron_stores": len(stores_out),
            "script_jobs": script_jobs,
            "enabled_script_jobs": enabled_script_jobs,
            "checked_paths": len(checked_paths),
            "critical_count": len(crit),
            "warning_count": len(warn),
            "advisory_count": len(advisory),
            "first_run_pending_count": len(first_pending),
        },
        "first_run_pending": first_pending[:50],
        "issues": issues,
    }


def render_markdown(report: dict[str, Any], propose_fixes: bool = False) -> str:
    lines = [f"## Hermes Cron Preflight — {report['status'].upper()}", f"Time: {report['timestamp']}", ""]
    s = report["summary"]
    lines.extend([
        "Summary:",
        f"- cron stores: {s['cron_stores']}",
        f"- script jobs: {s['script_jobs']}",
        f"- enabled script jobs: {s['enabled_script_jobs']}",
        f"- checked paths: {s['checked_paths']}",
        f"- critical: {s['critical_count']}",
        f"- warnings: {s['warning_count']}",
        f"- advisories: {s.get('advisory_count', 0)}",
        f"- first-run pending (not failures): {s.get('first_run_pending_count', 0)}",
        "",
    ])
    pending = report.get("first_run_pending") or []
    if pending:
        lines.append("First-run pending script jobs:")
        for item in pending[:12]:
            lines.append(f"- {item.get('profile')} / {item.get('job_name')} ({item.get('job_id')}): next={item.get('next_run_at')}")
        lines.append("")
    if report["issues"]:
        lines.append("Findings:")
        for i in report["issues"][:40]:
            lines.append(f"- {i['severity'].upper()} {i['code']}: {i['job_name']} ({i['job_id']})")
            lines.append(f"  - store/profile: {i['store']} / {i.get('profile') or 'default'}")
            lines.append(f"  - path: `{i['resolved_path']}`")
            lines.append(f"  - detail: {i['detail']}")
            if propose_fixes:
                lines.append(f"  - proposed fix: {i['proposal']}")
        if len(report["issues"]) > 40:
            lines.append(f"- ... {len(report['issues']) - 40} more findings in JSON report")
    else:
        lines.append("Findings: none — all enabled script cron paths resolve and syntax checks passed.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write-report", action="store_true")
    ap.add_argument("--propose-fixes", action="store_true")
    args = ap.parse_args()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report = scan()
    if args.write_report:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        (REPORT_DIR / f"cron-preflight-{stamp}.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (REPORT_DIR / "cron-preflight-latest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (REPORT_DIR / "cron-preflight-latest.md").write_text(render_markdown(report, propose_fixes=args.propose_fixes))
        if args.propose_fixes and report["issues"]:
            (REPORT_DIR / "cron-preflight-proposed-fixes.md").write_text(render_markdown(report, propose_fixes=True))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_markdown(report, propose_fixes=args.propose_fixes), end="")
    return 2 if report["summary"]["critical_count"] else 1 if report["summary"]["warning_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
