#!/bin/bash
# Periodic edit-safety snapshot wrapper (run hourly from cron/launchd/systemd).
# Polling on a timer instead of a recursive file watcher avoids sustained
# filesystem-event CPU pressure. Logs locally only; never notifies channels.
set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SNAPSHOT="${EDIT_SAFETY_SNAPSHOT:-$SCRIPT_DIR/edit_safety_snapshot.py}"
LOG_DIR="$HERMES_HOME/logs"
LOG="$LOG_DIR/edit-safety-watch.log"
LOCK_DIR="$HERMES_HOME/state/edit-safety-snapshot.lock"
LOG_MAX_BYTES="${EDIT_SAFETY_LOG_MAX_BYTES:-5242880}"

mkdir -p "$LOG_DIR" "$HERMES_HOME/state"

# Self-rotation: an unrotated hourly log eventually fills the disk.
if [ -f "$LOG" ]; then
  size=$(wc -c < "$LOG" | tr -d ' ')
  if [ "${size:-0}" -gt "$LOG_MAX_BYTES" ]; then
    mv -f "$LOG" "$LOG.1"
    : > "$LOG"
  fi
fi

log() { echo "$(date '+%Y-%m-%dT%H:%M:%S%z') $*" >> "$LOG"; }

# mkdir is atomic: a second overlapping run exits instead of racing.
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  log "skipped: lock held"
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

if [ ! -f "$SNAPSHOT" ]; then
  log "snapshot script missing: $SNAPSHOT"
  exit 1
fi

log "snapshot started"
if python3 "$SNAPSHOT" --reason periodic "$@" >> "$LOG" 2>&1; then
  log "snapshot finished"
else
  rc=$?
  log "snapshot failed rc=$rc"
  exit "$rc"
fi
