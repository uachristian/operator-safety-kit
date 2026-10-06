# Pre-push checklist (public or shared repositories)

Run this before the first push of a new repo, and before any push that adds files.

## Automated gates

- [ ] `python3 tools/public_gate.py . --denylist <path-outside-repo> --env-glob '<your env files>'` exits 0
- [ ] `python3 tools/privacy_gate.py --denylist <path-outside-repo> origin/main..HEAD` exits 0
      (first push: `python3 tools/privacy_gate.py $(git rev-list HEAD)` scans every commit)
- [ ] Test suite passes; every script byte-compiles / `bash -n` clean
- [ ] `hooks/pre-push.sample` installed as `.git/hooks/pre-push`

An empty scan (exit 2) is a failure, not a pass. Fix content; never weaken a
pattern or add a waiver to get green.

## Manual review

- [ ] Commit author/committer use a noreply identity
- [ ] No `.env`, keys, `*.pem`, databases, session/memory/log dumps, `state/` or backups
- [ ] Example configs use `example.com`, `127.0.0.1` and obviously fake IDs
- [ ] No absolute home paths; code resolves `HERMES_HOME` (or equivalent) at runtime
- [ ] No owner/business/customer names, host aliases, chat or user IDs, phone numbers
- [ ] Test fixtures that need secret-shaped strings build them at runtime (string concatenation), never as literal tokens
- [ ] Commit messages are also clean (they are public too)
- [ ] The denylist itself is not in the repo and is not quoted in any file, issue or PR

## If something leaked

1. Rotate the credential **first**. Rewriting history doesn't un-leak a secret.
2. Then purge it from history and force-push, and ask the host to drop cached views.
3. File an incident report (`templates/incident-report.md`).
