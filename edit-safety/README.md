# edit-safety

Agents edit shared files: skills, prompts, profile SOUL files, scripts. These
tools make those edits recoverable and visible.

| File | Prevents |
|---|---|
| `edit_safety_snapshot.py` | An agent overwrites a good skill/prompt and nobody can get the old one back. Mirrors selected files into a private local git repo and commits on change. |
| `edit-safety-periodic-snapshot.sh` | Snapshot runs that overlap, logs that fill the disk, watcher CPU burn. Lock dir, size-capped log, timer instead of a recursive watcher. |
| `drift_watch.py` | Silent drift between a declared source-of-truth repo and the deployed copy. Read-only, alerts after N consecutive runs, quiet when healthy. |

## Quickstart

```bash
# one snapshot of $HERMES_HOME/SOUL.md, skills/*/*/SKILL.md and profiles/*/SOUL.md
# (repo created mode 0700). Scheduling it hourly is OPTIONAL and needs owner go;
# never schedule it during bootstrap.
./edit-safety-periodic-snapshot.sh

# custom tracked set
python3 edit_safety_snapshot.py --config my-snapshot.json --reason "before refactor"

# drift
python3 drift_watch.py --config drift.example.json --check
```

Restore a file: `git -C "$HERMES_HOME/state/edit-safety-repo" log -- snapshot/skills/<cat>/<name>/SKILL.md`,
then `git show <rev>:<path>` into a scratch file, diff it, and copy it back
deliberately. Snapshot first, then restore, so the bad version is also kept.

Two rules:

- A missing or empty source is skipped, never mirrored as empty. A short
  mount or sync outage can't erase the last good snapshot.
- The snapshot repo is private recovery material. Never add a remote to it.
