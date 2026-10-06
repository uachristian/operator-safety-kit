# operator-safety-kit

Small, stdlib-only safety tooling for people who run AI agents against real
systems: chat gateways, cron jobs, CRMs, mailboxes, public repos.

It came out of running a multi-profile [Hermes Agent](https://github.com/NousResearch/hermes-agent)
fleet, but nothing here imports Hermes. The only coupling is the default
state location: `$HERMES_HOME`, which falls back to `~/.hermes`.

## What each piece prevents

| Path | Prevents |
|---|---|
| `tools/public_gate.py` | Publishing a repo that contains home paths, emails, private/tailnet IPs, phone numbers, token-shaped strings, chat IDs, forbidden files (`.env`, keys, DBs, logs, sessions), symlinks, denylisted names, or the **exact values** of your local secrets. Reports category + `path:line` only, never the match. An empty scan exits 2: no files is never a pass. |
| `tools/privacy_gate.py` | The same leaks in **commits**: messages, non-noreply author/committer identities, and added diff lines. Owner names, business names, host aliases and chat IDs come from an external denylist, not from the code. |
| `tools/denylist.example.txt` | Format reference only (obviously fake terms). Keep your real denylist outside every repo. |
| `guards/wrap_untrusted.py` | Prompt injection from web pages, email, vendor portals, chat and customer-typed record fields. Strips HTML, invisible and bidi characters, and known jailbreak phrases, then length-caps the text and wraps it in nonce-tagged `<UNTRUSTED_INPUT_xxxx>` delimiters with a "this is data" reminder. |
| `guards/output_gate.py` | An injected agent leaking secrets or phishing links. Secrets and suspicious URLs (any IP-literal host in dotted, decimal, hex, octal, short or IPv6 form; shorteners; punycode or non-ASCII hosts) are always hard-blocked; unparseable URLs block in `enforce`. Unknown domains, length and rate limits warn in `log_only` and block in `enforce`. An unknown mode fails closed. The audit log keeps hashes, not text. |
| `guards/capability_gate.py` | Autonomous cron runs, non-owner chat users, or context-less callers calling write tools. Fails closed: a tool is a read only if it is on an explicit read allowlist (everything else, including unknown names, is a write), and missing session context never grants owner. Owner IDs come from a config file. |
| `edit-safety/` | Unrecoverable agent edits to skills, prompts and SOUL files (private git snapshot mirror), plus silent drift between a source repo and the deployed copy. |
| `ops-monitoring/` | Silent fleet failures: dead services, broken cron script paths, config parse errors, failing endpoints, unclassified new inventory. Read-only scripts with an ops-profile SOUL template. |
| `templates/` | Changes made with no backup or restore proof, incidents with no write-up, pushes with no review. |
| `hooks/pre-push.sample` | Forgetting to run the gates. |

## Install

Put the kit at `$HERMES_HOME/safety-kit` (`HERMES_HOME` defaults to `~/.hermes`):

```bash
cp -R operator-safety-kit "${HERMES_HOME:-$HOME/.hermes}/safety-kit"
cd "${HERMES_HOME:-$HOME/.hermes}/safety-kit"
python3 -m unittest discover -s tests      # must be all OK before wiring anything
```

Bootstrap installs files and runs the tests. That's all it does. The hourly
`edit-safety` snapshots and the `ops-monitoring` crons are **optional**. Don't
schedule them during bootstrap. The owner has to say go first.

## Quickstart

```bash
# 1. Public-release gate on a staged tree (denylist lives OUTSIDE the tree)
python3 tools/public_gate.py path/to/repo \
    --denylist "${HERMES_HOME:-$HOME/.hermes}/state/public-repos/denylist.txt" \
    --env-glob "${HERMES_HOME:-$HOME/.hermes}/.env" \
    --env-glob "${HERMES_HOME:-$HOME/.hermes}/profiles/*/.env"

# 2. Commit privacy gate on what you are about to push
python3 tools/privacy_gate.py --repo path/to/repo origin/main..HEAD

# 3. Install the hook
cp hooks/pre-push.sample path/to/repo/.git/hooks/pre-push
chmod +x path/to/repo/.git/hooks/pre-push
export SAFETY_KIT_DIR="${HERMES_HOME:-$HOME/.hermes}/safety-kit"   # where tools/ lives

# 4. Tests (from the kit directory)
python3 -m unittest discover -s tests
```

Exit codes for both gates: `0` clean, `1` findings, `2` usage error or empty scan.

## How an agent should wire these

The three guards are layers. Each assumes the one before it can fail.

```text
 external content ──► wrap_untrusted ──► model ──► capability_gate ──► tool
                                           │
                                           └──► output_gate ──► chat / email / SMS
 git push ──► pre-push hook ──► public_gate + privacy_gate ──► remote
```

### 1. Wrap everything you did not write

Anything an outsider can influence goes through `wrap_untrusted` **before** it
goes into a prompt: fetched web pages, email bodies and subjects, vendor portal
text, inbound chat messages from non-owners, voicemail transcripts, and
CRM/ticket fields typed by customers.

```python
from guards import wrap_web_content, wrap_email, wrap_vendor_content, wrap_record_field

prompt = f"Extract the ETA from this vendor update:\n\n{wrap_vendor_content(raw, vendor='example-supplier')}"
```

Don't unwrap and re-inject the content in a later step. Pass the wrapped string
along. Extend the jailbreak list from your own incidents: copy
`guards/known_jailbreaks.sample.txt` to `known_jailbreaks.txt`.

### 2. Gate every outbound message

Call `check_message` right before any send to chat, email or SMS, and check the
verdict:

```python
from guards import check_message

v = check_message(draft, destination="telegram", agent="assistant")
if not v.allowed:
    log.warning("blocked outbound: %s", v.reasons)   # reasons are labels, not content
else:
    send(draft)
```

Roll out in `log_only` (`OUTPUT_GATE_MODE=log_only`). Then copy
`guards/domain_allowlist.sample.txt` to `domain_allowlist.txt`, list your real
domains, and switch to `enforce`. Use `check_record_write(tool, payload)` for
structured writes into business systems. Pass `skip_rate_limit=True` only for
direct replies to the owner.

### 3. Tier every tool call

At the top of the tool dispatcher:

```python
from guards import check_tool_call

denied = check_tool_call(server_name, tool_name)
if denied:
    return denied   # structured error back to the model; nothing executed
```

Put owner IDs in `$HERMES_HOME/security/owner_ids.json`
(`{"telegram": ["<id>"]}`) and allowed team writes in
`$HERMES_HOME/security/team_write_whitelist.txt`. Set `HERMES_CRON_SESSION=1`
in scheduler processes. If your runtime keeps per-turn context in contextvars,
inject a reader with `set_session_reader`. Once a reader is injected, every key
comes from it, including the cron flag.

The gate fails closed in two ways:

- **Owner needs a positive signal.** That means `HERMES_SESSION_PLATFORM` is
  set to `cli`, `local` or `desktop`, or the platform user ID is in the owner
  file. Empty or missing context gets tier `unknown`: reads only, every write
  denied. Interactive local front-ends must set the platform explicitly.
- **Only allowlisted names count as reads.** Names are normalized first:
  camelCase and hyphens become snake_case, and `mcp_` and server prefixes are
  stripped. A name is a read if it matches a built-in read name (`read_file`,
  `web_search`, ...) or starts with a read verb (`get_`, `list_`, `search_`,
  `read_`, `find_`, `view_`, `show_`, `describe_`, `lookup_`) and has no write
  verb in it. Everything else is a write. To add reads, list exact names or
  `prefix:<verb>` lines in `$HERMES_HOME/security/read_tool_allowlist.txt`.

### 4. Gate every push

Install `hooks/pre-push.sample` as `.git/hooks/pre-push` in every repo that
could ever become public, with `SAFETY_KIT_DIR` pointing at the kit. The hook
blocks the push when the denylist or `tools/privacy_gate.py` is missing. Set
`SAFETY_KIT_ALLOW_NO_DENYLIST=1` only as a deliberate opt-out. Fix findings by
changing the content. The gates have no waiver flag, and you shouldn't weaken
the patterns. Test fixtures that need secret-shaped strings must build them at
runtime (see `tests/`).

**Filled-in SOUL.md / AGENTS.md / persona files will be flagged by the gate.**
That's expected, because they hold owner names, IDs, hosts and business
details. Never publish them. Only the `*.template.md` files with `<...>`
placeholders belong in a public repo.

### 5. Monitor and keep things recoverable (optional, owner go required)

Once the owner approves, you can run `ops-monitoring/` from no-agent crons
(`examples/cron/`) and take `edit-safety` snapshots hourly. Neither is part of
bootstrap. Follow `templates/backup-and-rollback.md` before production changes.

## Configuration summary

| Item | Location |
|---|---|
| Denylist | anywhere outside the repo; hook default `$HERMES_HOME/state/public-repos/denylist.txt` |
| Domain allowlist | `guards/domain_allowlist.txt` (sample provided) or `set_allowlist_file()` |
| Jailbreak regexes | `guards/known_jailbreaks.txt` (sample provided) or `set_jailbreak_file()` |
| Kit install location | `$HERMES_HOME/safety-kit` |
| Owner IDs / team whitelist / read allowlist | `$HERMES_HOME/security/owner_ids.json`, `team_write_whitelist.txt`, `read_tool_allowlist.txt` |
| Fleet-health noise / log skips | `$HERMES_HOME/profiles/ops/fleet_health.json` (example in `ops-monitoring/examples/`) |
| Gate state and audit logs | `$HERMES_HOME/security/state/`, `$HERMES_HOME/logs/` |

## Limits

These are guardrails, not proofs. Regex scanners miss novel secret formats and
can't judge context. Injection filtering lowers the odds of an attack working;
it doesn't remove them. The output gate can't tell that a well-formed message
is wrong. Keep a human approval step for anything irreversible.

## License

MIT. See `LICENSE`.
