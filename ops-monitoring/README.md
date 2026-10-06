# ops-monitoring

Read-only fleet monitoring for a multi-profile agent install, driven by
no-agent crons (deterministic scripts; the LLM is not in the liveness path).

| File | Prevents |
|---|---|
| `fleet_health.py` | Silent outages and unmonitored additions. Discovers profiles, cron stores, scripts, launchd services and declared monitors; flags config/cron parse failures, `.env` mode drift, script syntax errors, dead critical services, failing endpoints and `NEW_INVENTORY`. Log hits are fingerprints only. |
| `cron_preflight.py` | Crons that fail at 3am with "Script not found". Resolves every enabled script job the way the scheduler will (profile vs root), checks existence, exec bit and syntax, and writes fix *proposals*. Exit 0 / 1 warn / 2 critical. |
| `ops-fleet-health-daily.sh` | Daily summary wrapper. |
| `ops-fleet-watchdog.sh` | Critical-only wrapper: silent while healthy. |
| `ops-profile-SOUL.template.md` | An ops agent that "fixes" production. Read-only default and explicit authority boundaries. |
| `examples/` | Monitor manifest, cron definitions, extra critical-label list, `fleet_health.example.json` (log noise patterns and per-profile log skips). |

## Install sketch

```bash
hermes profile create ops --no-skills --description "Fleet IT / reliability operator"
OPS="${HERMES_HOME:-$HOME/.hermes}/profiles/ops"
cp ops-profile-SOUL.template.md "$OPS/SOUL.md"        # then fill placeholders
mkdir -p "$OPS/scripts" "$OPS/monitors.d"
cp fleet_health.py cron_preflight.py *.sh "$OPS/scripts/"
chmod +x "$OPS/scripts/"*
cp examples/monitors.d/core-endpoints.example.json "$OPS/monitors.d/core-endpoints.json"
python3 "$OPS/scripts/fleet_health.py" --update-baseline --write-report
```

Scheduling the crons in `examples/cron/` is optional. Don't do it during
bootstrap. Wait for an explicit go from the owner.

Fleet root resolution: `HERMES_FLEET_ROOT`, else `HERMES_HOME` (a
`.../profiles/<name>` value is lifted to the install root), else `~/.hermes`.
