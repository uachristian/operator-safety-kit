#!/usr/bin/env python3
"""Snapshot agent-edited shared files into a private local git safety repo.

Non-invasive: never git-inits the live directories. Selected files are
mirrored into a separate repo and committed there, which gives diffs, history
and rollback material without touching how the agent loads skills/profiles.

Defaults (HERMES_HOME defaults to ~/.hermes):
  tracked: $HERMES_HOME/SOUL.md (default profile), $HERMES_HOME/skills/*/*/SKILL.md,
           $HERMES_HOME/profiles/*/SOUL.md
  repo:    $HERMES_HOME/state/edit-safety-repo (created mode 0700)

Override with a JSON config (--config FILE):
  {"repo": "/path/to/safety-repo",
   "tracked": [{"base": "/path", "pattern": "**/*.md", "prefix": "notes"}]}

Safety: a source base that is missing or currently empty is SKIPPED, not
mirrored as empty, so a transient mount/sync miss cannot wipe the last good
snapshot. The manifest is deterministic so unchanged inputs make no commit.
This repo is private recovery material; never push it anywhere.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

EXCLUDE_PARTS = {".git", "node_modules", "__pycache__"}


def hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()


def default_config() -> dict:
    h = hermes_home()
    return {
        "repo": str(h / "state" / "edit-safety-repo"),
        "tracked": [
            {"base": str(h), "pattern": "SOUL.md", "prefix": "root"},
            {"base": str(h / "skills"), "pattern": "*/*/SKILL.md", "prefix": "skills"},
            {"base": str(h / "profiles"), "pattern": "*/SOUL.md", "prefix": "profiles"},
        ],
    }


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=str(repo), text=True, capture_output=True, check=check)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(repo, 0o700)  # private recovery material; mkdir mode is umask-filtered
    if not (repo / ".git").exists():
        git(repo, "init", "-q")
        git(repo, "config", "user.name", "Edit Safety Snapshot")
        git(repo, "config", "user.email", "edit-safety@example.com")
        git(repo, "config", "commit.gpgsign", "false")
    (repo / "snapshot").mkdir(exist_ok=True)


def snapshot(cfg: dict, reason: str) -> dict:
    repo = Path(cfg["repo"]).expanduser()
    ensure_repo(repo)
    root = repo / "snapshot"
    copied: list[tuple[Path, Path]] = []
    skipped: list[str] = []
    for t in cfg["tracked"]:
        base = Path(t["base"]).expanduser()
        prefix = t["prefix"]
        if not base.exists():
            skipped.append(f"missing:{prefix}")
            continue
        files = [p for p in sorted(base.glob(t["pattern"]))
                 if p.is_file() and not (set(p.parts) & EXCLUDE_PARTS)]
        if not files:
            skipped.append(f"empty:{prefix}")
            continue
        target = root / prefix
        if target.exists():
            shutil.rmtree(target)
        for src in files:
            dst = target / src.relative_to(base)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied.append((src, dst))
    lines = ["# Edit Safety Snapshot", "", "Private recovery mirror. Not a source of truth. Never push.", "", "## Files", ""]
    lines += [f"- `{dst.relative_to(repo)}` sha256={sha256(src)}" for src, dst in copied]
    (repo / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    git(repo, "add", "-A", "MANIFEST.md", "snapshot")
    if not git(repo, "status", "--porcelain").stdout.strip():
        return {"changed": False, "files": len(copied), "skipped": skipped}
    git(repo, "commit", "-q", "-m", f"snapshot: {reason} ({datetime.now():%Y-%m-%d %H:%M:%S})")
    commit = git(repo, "rev-parse", "--short", "HEAD").stdout.strip()
    return {"changed": True, "files": len(copied), "commit": commit, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reason", default="manual")
    ap.add_argument("--config")
    a = ap.parse_args(argv)
    cfg = json.loads(Path(a.config).read_text()) if a.config else default_config()
    try:
        print(json.dumps(snapshot(cfg, a.reason)))
    except subprocess.CalledProcessError as e:
        print(e.stderr, end="", file=sys.stderr)
        return e.returncode or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
