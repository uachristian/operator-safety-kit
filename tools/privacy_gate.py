#!/usr/bin/env python3
"""Privacy gate for outbound commits (pre-push / pre-PR).

Scans commit messages, author/committer identity, and ADDED diff lines for
private data. Never prints matched values: reports category, file and line
number only.

Owner-specific terms (personal names, business names, host aliases, chat or
user IDs) are NOT hardcoded. They come from an external denylist file that
lives outside the repository being scanned.

Usage:
  privacy_gate.py [--repo DIR] [--denylist FILE] [--env-glob GLOB ...] REV...

  REV is a commit, or a range like origin/main..HEAD.

Denylist format (one entry per line, '#' comments):
  plain term           case-insensitive word match (spaces also match _ and -)
  re:<regex>           raw case-insensitive regex (use for ID shapes)

Default denylist: $HERMES_HOME/state/public-repos/denylist.txt (HERMES_HOME
defaults to ~/.hermes) when that file exists.
Default env globs: $HERMES_HOME/.env and $HERMES_HOME/profiles/*/.env.

Exit codes: 0 clean, 1 findings, 2 usage error / nothing to scan.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "home_path": re.compile(r"/Users/[A-Za-z0-9._-]+|/home/[a-z][a-z0-9_-]+/|C:\\\\?Users\\\\?[A-Za-z]", re.I),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@(?!(?i:example\.(com|org|net)|users\.noreply\.github\.com)(?![A-Za-z0-9-]|\.[A-Za-z0-9]))[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "tailnet": re.compile(r"\btail[0-9a-f]{6}\.ts\.net|\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b", re.I),
    "private_ip": re.compile(r"\b(192\.168|10\.\d{1,3}|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    "phone": re.compile(r"(?<![\w.])\+?1?[\s.-]?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
    "token_shape": re.compile(
        r"sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}"
        r"|\b\d{8,10}:AA[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.|AIza[0-9A-Za-z_-]{35}"),
    "telegram_or_slack_id": re.compile(r"(?<![\w.-])-100\d{9,}\b|(?<![\w.-])-\d{10}\b|\bU[0-9A-Z]{8,10}\b(?=.*slack)|\b[CU]0[0-9A-Z]{9,10}\b"),
}
ALLOWED_IDENTITY = re.compile(r"^[^<>]+ <\d*\+?[A-Za-z0-9-]+@users\.noreply\.github\.com>$", re.I)
SECRETISH_KEY = re.compile(r"KEY|TOKEN|SECRET|PASS|AUTH|CRED|PRIVATE|COOKIE|SESSION|WEBHOOK", re.I)


def hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()


def default_denylist() -> str | None:
    p = hermes_home() / "state" / "public-repos" / "denylist.txt"
    return str(p) if p.is_file() else None


def default_env_globs() -> list[str]:
    h = hermes_home()
    return [str(h / ".env"), str(h / "profiles" / "*" / ".env")]


def load_denylist(path: str | None) -> list[re.Pattern[str]]:
    if not path:
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("re:"):
            out.append(re.compile(line[3:], re.I))
        else:
            term = re.escape(line.lower()).replace(r"\ ", r"[\s_-]*")
            out.append(re.compile(r"(?<![a-z0-9])" + term + r"(?![a-z0-9])", re.I))
    return out


def load_secret_values(globs: list[str]) -> set[str]:
    """Exact secret values from local env files; compared, never printed."""
    vals: set[str] = set()
    for g in globs:
        for f in glob.glob(os.path.expanduser(g)):
            try:
                lines = open(f, errors="ignore").read().splitlines()
            except OSError:
                continue
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip().strip("'\"")
                if len(v) < 10 or v.lower() in ("true", "false"):
                    continue
                if re.fullmatch(r"[a-z][a-z0-9._/_-]*", v) and not SECRETISH_KEY.search(k):
                    continue  # plain identifiers like provider names are not secrets
                vals.add(v)
    return vals


class Git:
    def __init__(self, repo: str | None):
        self.base = ["git"] + (["-C", repo] if repo else [])

    def __call__(self, *a: str) -> str:
        return subprocess.run(self.base + list(a), capture_output=True, text=True, errors="replace").stdout


def scan_line(text: str, where: str, ln: int, deny, secrets, out: list) -> None:
    for cat, rx in PATTERNS.items():
        if rx.search(text):
            out.append((cat, where, ln))
    if any(rx.search(text) for rx in deny):
        out.append(("denylist_term", where, ln))
    if any(s in text for s in secrets):
        out.append(("exact_local_secret", where, ln))


def scan_commit(git: Git, c: str, deny, secrets) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for who in git("log", "-1", "--format=%an <%ae>%n%cn <%ce>", c).splitlines():
        if not ALLOWED_IDENTITY.match(who):
            out.append(("identity_not_noreply", "<commit>", 0))
    for i, line in enumerate(git("log", "-1", "--format=%B", c).splitlines(), 1):
        scan_line(line, "<message>", i, deny, secrets, out)
    cur, ln = None, 0
    for line in git("show", "--format=", "--unified=0", "--no-color", c).splitlines():
        if line.startswith("+++ "):
            cur = line[6:] if line.startswith("+++ b/") else line[4:]
            if cur and any(rx.search(cur) for rx in deny):
                out.append(("denylist_term", cur, 0))
            continue
        m = re.match(r"@@ -\S+ \+(\d+)", line)
        if m:
            ln = int(m.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            scan_line(line[1:], cur or "?", ln, deny, secrets, out)
            ln += 1
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("revs", nargs="*")
    ap.add_argument("--repo")
    ap.add_argument("--denylist", default=None)
    ap.add_argument("--env-glob", action="append", default=None)
    a = ap.parse_args(argv)
    git = Git(a.repo)
    if not a.revs:
        print("FAIL no commits to scan (an empty scan is never a pass)")
        return 2
    commits: list[str] = []
    for r in a.revs:
        got = git("rev-list", "--reverse", r).split() if ".." in r else git("rev-parse", "--verify", "-q", r + "^{commit}").split()
        if not got and ".." not in r:
            print(f"FAIL could not resolve '{r}' to any commit")
            return 2
        commits += got
    if not commits:
        print("FAIL no commits to scan (an empty scan is never a pass)")
        return 2
    deny_path = a.denylist if a.denylist is not None else default_denylist()
    if deny_path and not Path(deny_path).is_file():
        print("FAIL denylist file not found")
        return 2
    deny = load_denylist(deny_path)
    secrets = load_secret_values(a.env_glob if a.env_glob is not None else default_env_globs())
    bad = 0
    for c in commits:
        f = scan_commit(git, c, deny, secrets)
        short = git("log", "-1", "--format=%h", c).strip()
        if f:
            bad += 1
            cats: dict[str, list[str]] = {}
            for cat, path, ln in f:
                cats.setdefault(cat, []).append(f"{path}:{ln}")
            print(f"FAIL {short}")
            for cat, locs in cats.items():
                print(f"   {cat}: {len(locs)} -> {', '.join(locs[:4])}")
        else:
            print(f"PASS {short}")
    print(f"\n{len(commits)} commits, {bad} with findings, {len(deny)} denylist entries, "
          f"{len(secrets)} local secret values checked (not shown)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
