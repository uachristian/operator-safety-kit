#!/bin/bash
# Daily fleet report. Writes reports/latest.{md,json} under the ops profile and
# prints the markdown summary (the cron delivers stdout to the owner).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/fleet_health.py" --write-report
