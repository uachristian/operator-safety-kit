#!/bin/bash
# Frequent critical-only watchdog. Prints nothing while healthy, so a
# no-agent cron delivers a message only when something is red or new.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/fleet_health.py" --critical-only --write-report
