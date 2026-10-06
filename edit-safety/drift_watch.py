#!/usr/bin/env python3
"""Source-authority drift watch: is the live copy still what the repo says?

Agents often edit *deployed* files (skills, scripts, prompts) directly. When a
git repo is the declared source of truth, those edits silently drift. This
read-only watcher compares tracked files in a source repo against their live
counterparts and alerts on drift with hysteresis:

- an issue alerts only after it persists CONFIRM_RUNS consecutive runs,
- an issue that disappears is dropped silently,
- one "resolved" line is emitted when every alerted issue clears,
- healthy runs print nothing (cron-friendly).

Config (JSON):
  {"mappings": [{"name": "my-skills", "repo": "/path/to/repo",
                 "repo_prefix": "skills", "live_root": "/path/to/live/skills",
                 "detect_extras": true}]}

Never writes to repos or live trees. State lives under
$HERMES_HOME/state/drift-watch/ (HERMES_HOME defaults to ~/.hermes).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable

CONFIRM_RUNS = 2
SOURCE_SUFFIXES = {".py", ".sh", ".md", ".json", ".yaml", ".yml", ".txt", ".toml"}
IGNORED_PARTS = {".git", "__pycache__", "node_modules", ".venv"}


def state_file() -> Path:
    home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()
    return home / "state" / "drift-watch" / "state.json"


def normalized(path: Path) -> bytes:
    data = path.read_bytes()
    if path.suffix.lower() == ".md":  # trailing-whitespace edits are not drift
        text = data.decode("utf-8", errors="replace")
        return ("\n".join(l.rstrip() for l in text.rstrip().splitlines()) + "\n").encode()
    return data


def same(a: Path, b: Path) -> bool:
    return hashlib.sha256(normalized(a)).digest() == hashlib.sha256(normalized(b)).digest()


def tracked_files(repo: Path, prefix: str) -> list[str]:
    r = subprocess.run(["git", "-C", str(repo), "ls-files", "--", prefix], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"git ls-files failed in {repo.name}")
    return [l for l in r.stdout.splitlines() if l]


def live_candidates(root: Path) -> set[str]:
    out: set[str] = set()
    if root.is_dir():
        for p in root.rglob("*"):
            if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES:
                rel = p.relative_to(root)
                if not any(part in IGNORED_PARTS or part.startswith(".") for part in rel.parts):
                    out.add(rel.as_posix())
    return out


def collect(cfg: dict) -> list[str]:
    issues: list[str] = []
    for m in cfg.get("mappings", []):
        name, repo = m["name"], Path(m["repo"]).expanduser()
        prefix = m.get("repo_prefix", "").rstrip("/")
        live_root = Path(m["live_root"]).expanduser()
        expected: set[str] = set()
        for repo_rel in tracked_files(repo, prefix or "."):
            rel = Path(repo_rel).relative_to(prefix).as_posix() if prefix else repo_rel
            expected.add(rel)
            live = live_root / rel
            if not live.is_file():
                issues.append(f"{name}: live missing {rel}")
            elif not same(repo / repo_rel, live):
                issues.append(f"{name}: live differs {rel}")
        if m.get("detect_extras"):
            issues += [f"{name}: unmirrored live file {x}" for x in sorted(live_candidates(live_root) - expected)]
    return sorted(set(issues))


def fingerprint(issues: Iterable[str]) -> str:
    issues = list(issues)
    return hashlib.sha256("\n".join(sorted(issues)).encode()).hexdigest() if issues else "clean"


def decide(previous: dict, issues: list[str], confirm_runs: int = CONFIRM_RUNS) -> tuple[dict, list[str]]:
    """Pure state transition: (new_state, lines_to_print)."""
    old = {k: int(v) for k, v in (previous.get("streak") or {}).items()}
    alerted = set(previous.get("alerted") or [])
    current = set(issues)
    streak = {i: old.get(i, 0) + 1 for i in current}
    alerted &= current
    confirmed = {i for i, n in streak.items() if n >= confirm_runs}
    new = sorted(confirmed - alerted)
    lines: list[str] = []
    if new:
        lines.append(f"Source drift: {len(new)} new issue(s) confirmed over {confirm_runs} runs ({len(confirmed)} open):")
        lines += [f"- {i}" for i in new[:20]]
        if len(new) > 20:
            lines.append(f"- plus {len(new) - 20} more; run with --check")
        alerted |= set(new)
    elif not current and previous.get("alerted"):
        lines.append("Source drift resolved: all watched mappings aligned.")
    return {"streak": streak, "alerted": sorted(alerted), "fingerprint": fingerprint(issues)}, lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--check", action="store_true", help="print all current issues, no state change")
    a = ap.parse_args(argv)
    cfg = json.loads(Path(a.config).read_text())
    try:
        issues = collect(cfg)
    except (OSError, RuntimeError, ValueError) as e:
        print(f"drift-watch check error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if a.check:
        print("\n".join(issues) if issues else "clean")
        return 1 if issues else 0
    sf = state_file()
    try:
        prev = json.loads(sf.read_text())
    except (OSError, ValueError):
        prev = {}
    state, lines = decide(prev if isinstance(prev, dict) else {}, issues)
    sf.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = sf.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, sort_keys=True, indent=1) + "\n")
    os.replace(tmp, sf)
    if lines:
        print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
