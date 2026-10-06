# Backup and rollback checklist

Use before any change to a production system, agent profile, cron, service,
database or credential store. Pick the smallest backup lane that actually
covers the change. Don't turn a one-line script fix into a full secrets dump,
and don't answer a full-recovery request with a source-only snapshot.

## 0. Prove where you are

- [ ] Actual user, home, profile, working directory and runtime root confirmed (not assumed).
- [ ] Explicit source and destination paths written down.
- [ ] Any environment overrides are scoped to one process, not exported globally.

## 1. Classify every source

| Source | REQUIRED / OPTIONAL / FORBIDDEN | Notes |
|---|---|---|
| `<path>` | | |

- A failing REQUIRED source fails the backup. Never quietly downgrade it to optional.
- Expected optional exclusions are listed in the manifest. An unexpected read error is still an error.

## 2. Choose the lane

- **Small edit snapshot:** only the touched files plus their metadata and rollback notes. No secrets. Strip secret-like env/args from service definitions before recording them.
- **Full profile rollback:** hidden files, modes and metadata. Identify bridges, shims and centrally owned files. Destination sits outside the profile. Capture mutable databases consistently: a raw copy of a live directory is not a coherent database backup.
- **Live database:** use the engine's online-backup API or a read-snapshot (for SQLite: an explicit read transaction, then `Connection.backup`), and hash the exact bytes you staged. Keep backup freshness and restore proof as separate results.
- **Schema/permission change:** capture ACLs, owners and default privileges plus an executable forward and rollback script. A schema dump alone won't roll back an authority change.

## 3. Create and verify before changing anything

- [ ] Backup created **before** the edit and before any deletion or rotation.
- [ ] Destination outside the source tree, owner-only modes (dirs 0700, files 0600).
- [ ] Manifest: exact inventory, sizes, SHA-256, exclusions, source identity (commit/version), timestamp.
- [ ] Anything leaving the host (cloud, removable, remote) is encrypted with authenticated encryption. File modes are not encryption.
- [ ] Capacity: free space covers peak staging plus restore footprint plus margin. Copy-on-write clone sizes don't tell you how much space you'd reclaim.

## 4. Restore proof

- [ ] Restore into a disposable, isolated location (temp dir / container / scratch DB), not over the original.
- [ ] Verify integrity (hash match, `PRAGMA integrity_check`, app-level smoke test).
- [ ] Checksums and a readable archive are **not** restore proof. Only a successful restore is.
- [ ] Keep the previous good backup until the new one has passed restore proof.

## 5. Make the change

- [ ] One change at a time, with a stated verification command and expected output.
- [ ] Verify. If verification fails, roll back first and investigate second.

## 6. Rollback procedure (fill in before the change)

```text
1. Stop: <service/cron to pause>
2. Restore: <exact copy/restore command from the verified backup>
3. Verify: <command> -> <expected output>
4. Resume: <service/cron to re-enable>
```

## 7. Retention and cleanup

- [ ] No guessed, broad or automatic deletion. List exact paths with their recovery value and get explicit approval.
- [ ] Right before deleting, check again: path, ownership, symlinks, and that no process has the file open.
- [ ] After deleting, show the items are gone **and** the backups you kept still restore.
- [ ] After a partial failure, look at what actually happened (PIDs, locks, markers, logs) before retrying. A lost tracking handle doesn't mean the job finished.

## Report

Created / retained / deleted items, measured space, verified recovery level,
what remains unproven, next approved action.
