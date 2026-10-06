"""Shared test helpers. Planted secrets/PII are assembled at runtime so no
literal secret-shaped token or private value ever sits in this repository."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_module(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# --- planted values (built by concatenation) ---
def fake_openai_key() -> str:
    return "s" + "k-" + "T3st" * 8


def fake_github_token() -> str:
    return "gh" + "p_" + "A1b2C3d4" * 5


def fake_bot_token() -> str:
    return "1234" + "56789" + ":" + "AA" + "x" * 33


def fake_private_key_header() -> str:
    return "-----" + "BEGIN RSA " + "PRIVATE KEY" + "-----"


def fake_home_path() -> str:
    return "/" + "Users" + "/" + "someone" + "/project"


def fake_email() -> str:
    return "jane.doe" + "@" + "corp-internal" + ".io"


def fake_private_ip() -> str:
    return ".".join(["192", "168", "7", "42"])


def fake_phone() -> str:
    return "(" + "415" + ") " + "555" + "-" + "0199"


def fake_local_secret() -> str:
    return "Zq" + "9vLx" * 5 + "Wm"


def git_env(home: Path) -> dict:
    env = dict(os.environ)
    env.update({
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Tester",
        "GIT_AUTHOR_EMAIL": "12345+tester" + "@users.noreply.github.com",
        "GIT_COMMITTER_NAME": "Tester",
        "GIT_COMMITTER_EMAIL": "12345+tester" + "@users.noreply.github.com",
    })
    return env


def git(repo: Path, *args: str, env: dict | None = None) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=env).stdout


def run_py(script: Path, *args: str, env: dict | None = None, cwd: Path | None = None):
    e = dict(env or os.environ)
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, str(script), *map(str, args)], capture_output=True,
                          text=True, env=e, cwd=str(cwd) if cwd else None)
