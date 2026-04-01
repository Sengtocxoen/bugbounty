# Workflow Status Tracker

> Updated by each session. Check this before starting any stage.

## Current Stage
- [ ] 0 — Auth Setup (establish session, document auth mechanism)
- [ ] 1 — Recon complete (subdomains, endpoints, tech stack mapped)
- [ ] 2 — Hunt complete (web/API/domain tested, findings created)
- [ ] 3 — Triage complete (all findings scored and decided)
- [ ] 4 — Chain analysis complete (combinations evaluated)
- [ ] 5 — Report drafts complete
- [ ] 6 — Counter-path review complete
- [ ] 7 — Improve loop complete → READY TO SUBMIT

## Auth Status
- **Authenticated:** YES / NO / PARTIAL
- **Session type:** cookie / JWT / API key
- **Session ID/token location:** <!-- where is it stored -->
- **Expires:** <!-- when does it need refreshing -->
- **Protocol notes:** <!-- HTTP/2 required? Special headers? -->

## Loop Count
- Current loop: 0
- Max loops before forcing human review: 3

## Findings Summary
| ID | Title | Severity | Triage (out of 25) | FP Risk | Report (out of 20) | Status |
|----|-------|----------|--------------------|---------|--------------------|--------|
| — | — | — | — | — | — | — |

## Blocked / Needs Human Input
```
# List anything that needs the user to answer or provide before continuing
# Format: [Finding ID] — What's needed — Why it's blocked
```

## Dropped Findings (and why)
```
# [Finding ID] — Reason for dropping
# This prevents re-investigating the same dead ends
```

## Session Log
```
# Append each session's summary here
# [date] [stage] — what was done, what was found, what's next
```
