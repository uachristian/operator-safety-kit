# Incident report: <short title>

- **ID:** <YYYY-MM-DD-slug>
- **Severity:** SEV1 / SEV2 / SEV3
- **Status:** open / mitigated / resolved
- **Detected:** <timestamp, tz> by <monitor / person / user report>
- **Resolved:** <timestamp, tz>
- **Owner:** <role, not personal contact details>

## Summary

Two or three sentences: what broke, who or what was affected, how it was stopped.

## Impact

- Affected systems/profiles/jobs:
- Affected users/customers (counts, not identities):
- Data exposure: none / suspected / confirmed (category only; never paste the data)
- Outbound actions taken by an agent during the incident (messages sent, records written):

## Timeline

| Time | Event | Source of evidence |
|---|---|---|
| | | |

## Root cause

What actually caused it, pointing at the exact line, config key or input.
Separate the trigger from the underlying weakness.

## Agent-specific questions

- [ ] Did untrusted content (web/email/vendor/chat) reach the model unwrapped?
- [ ] Did an outbound message bypass the output gate?
- [ ] Did a scheduled/autonomous session perform a write it should only have proposed?
- [ ] Was a deployed file edited directly instead of through its source repo?
- [ ] Did a secret appear in a log, report, commit or chat message? If yes: rotate first, then clean up.

## Mitigation and recovery

What was done, in order, and how each step was verified. Link the backup used
(see `backup-and-rollback.md`).

## Follow-ups

| Action | Prevents recurrence of | Owner | Due | Done |
|---|---|---|---|---|
| | | | | |

## Evidence

Paths to logs and reports (redacted). No raw secrets, tokens, personal data or
customer records in this document.
