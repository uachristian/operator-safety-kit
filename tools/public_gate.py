#!/usr/bin/env python3
"""Public-release gate for a staged repository tree.

Scans every tracked-or-untracked regular file under ROOT (skipping .git) for
private data and reports CATEGORY + path:line only (never the matched value).
Also checks git author/committer identities when ROOT is a git repo.

Exit codes: 0 clean, 1 findings, 2 usage/empty-scan error.

Usage:
  public_gate.py ROOT [--denylist FILE] [--env-glob GLOB ...]

The denylist (one lowercase term per line, '#' comments) lives OUTSIDE the
repo. Without one, only the generic patterns run. There are no waivers: fix a
finding by changing the content (build test fixtures at runtime).
"""
import argparse
import glob
import os
import re
import subprocess
import sys

PATTERNS = {
    "home_path": re.compile(r"/Users/[A-Za-z0-9._-]+|/home/[a-z][a-z0-9_-]+/|C:\\\\?Users\\\\?[A-Za-z]", re.I),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@(?!(?i:example\.(com|org|net)|users\.noreply\.github\.com)(?![A-Za-z0-9-]|\.[A-Za-z0-9]))[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "tailnet": re.compile(r"\b[a-z0-9-]+\.tail[0-9a-f]{4,}\.ts\.net|\btail[0-9a-f]{6}\.ts\.net|\b100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b", re.I),
    "private_ip": re.compile(r"\b(192\.168|10\.\d{1,3}|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    "phone": re.compile(r"(?<![\w.])\+?1?[\s.-]?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
    "token_shape": re.compile(
        r"sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}"
        r"|\b\d{8,10}:AA[A-Za-z0-9_-]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
        r"|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.|AIza[0-9A-Za-z_-]{35}"),
    "telegram_or_slack_id": re.compile(r"(?<![\w.-])-100\d{9,}\b|(?<![\w.-])-\d{10}\b|\bU[0-9A-Z]{8,10}\b(?=.*slack)|\b[CU]0[0-9A-Z]{9,10}\b"),
    "url_shortener": re.compile(r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd)/", re.I),
}
ALLOWED_IDENTITY = re.compile(r"^[^<>]+ <\d*\+?[A-Za-z0-9-]+@users\.noreply\.github\.com>$", re.I)
FORBIDDEN_NAMES = re.compile(r"(^|/)(\.env(\..*)?|auth\.json|hosts\.yml|.*\.pem|.*\.key|id_[a-z0-9]+|state\.db.*|.*\.sqlite3?|.*\.jsonl|sessions?|memories|logs?)$", re.I)
ALLOWED_ENV = re.compile(r"(^|/)\.env\.example$")
TEXT_LIMIT = 2_000_000


def load_terms(path):
    if not path:
        return []
    out = []
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def load_env_values(globs):
    vals = set()
    for g in globs:
        for f in glob.glob(os.path.expanduser(g)):
            try:
                for line in open(f, errors="ignore"):
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    v = v.strip().strip("'\"")
                    if len(v) < 10 or v.lower() in ("true", "false"):
                        continue
                    secretish = re.search(r"KEY|TOKEN|SECRET|PASS|AUTH|CRED|PRIVATE|COOKIE|SESSION|WEBHOOK", k, re.I)
                    if re.fullmatch(r"[a-z][a-z0-9._/_-]*", v) and not secretish:
                        continue
                    vals.add(v)
            except OSError:
                pass
    return vals


def term_regex(term):
    return re.compile(r"(?<![a-z0-9])" + re.escape(term).replace(r"\ ", r"[\s_-]*") + r"(?![a-z0-9])", re.I)


def iter_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            p = os.path.join(dp, fn)
            yield p, os.path.relpath(p, root)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--denylist")
    ap.add_argument("--env-glob", action="append", default=[])
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    terms = [(t, term_regex(t)) for t in load_terms(a.denylist)]
    secrets = load_env_values(a.env_glob)
    findings, scanned = [], 0
    for p, rel in iter_files(root):
        if os.path.islink(p):
            findings.append(("symlink", rel, 0)); continue
        if FORBIDDEN_NAMES.search(rel) and not ALLOWED_ENV.search(rel):
            findings.append(("forbidden_path", rel, 0))
        try:
            if os.path.getsize(p) > TEXT_LIMIT:
                findings.append(("oversize", rel, 0)); continue
            data = open(p, "rb").read()
        except OSError:
            findings.append(("unreadable", rel, 0)); continue
        if b"\0" in data[:8192]:
            findings.append(("binary_review", rel, 0)); continue
        scanned += 1
        text = data.decode("utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            for cat, rx in PATTERNS.items():
                if rx.search(line):
                    findings.append((cat, rel, i))
            low = line.lower()
            for t, rx in terms:
                if t in low.replace("_", " ").replace("-", " ") or rx.search(line):
                    findings.append(("denylist_term", rel, i)); break
            if any(s in line for s in secrets):
                findings.append(("exact_local_secret", rel, i))
    if os.path.isdir(os.path.join(root, ".git")):
        ids = subprocess.run(["git", "-C", root, "log", "--all", "--format=%an <%ae>%n%cn <%ce>"],
                             capture_output=True, text=True).stdout.splitlines()
        for who in set(ids):
            if who and not ALLOWED_IDENTITY.match(who):
                findings.append(("identity_not_noreply", "<git>", 0))
        msgs = subprocess.run(["git", "-C", root, "log", "--all", "--format=%B"], capture_output=True, text=True).stdout
        for i, line in enumerate(msgs.splitlines(), 1):
            low = line.lower()
            if any(rx.search(line) for _, rx in terms) or any(rx.search(line) for rx in PATTERNS.values()):
                findings.append(("commit_message", "<git>", i))
    if scanned == 0:
        print("FAIL empty scan (zero text files) is never a pass"); sys.exit(2)
    cats = {}
    for cat, rel, ln in findings:
        cats.setdefault(cat, []).append(f"{rel}:{ln}")
    for cat, locs in sorted(cats.items()):
        print(f"FAIL {cat}: {len(locs)} -> {', '.join(locs[:8])}")
    print(f"{scanned} text files scanned, {len(terms)} denylist terms, {len(secrets)} local secret values (not shown), {len(findings)} findings")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
