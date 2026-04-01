# Bug Bounty Orchestrator

> Paste the relevant prompt into a Claude Code session to start or resume.
> Each session reads program.md and STATUS.md to know what to do.

---

## START PROMPT (paste into Claude Code)

```
Read /home/kali/Desktop/bugbounty/bb-workspace/program.md and /home/kali/Desktop/bugbounty/bb-workspace/STATUS.md.

You are the bug bounty orchestrator. Run the full workflow below for the target in program.md. Update STATUS.md after each stage.

CRITICAL RULES:
- Read program.md "Out of Scope", "Known Issues", and "Previous Reports" BEFORE testing anything
- Never re-report something from "Previous Reports"
- Every finding MUST pass the Reality Check in the finding template BEFORE triage
- If you can't prove data ownership on an IDOR, mark it NEEDS_INFO, don't submit
- If a chain has an unproven link, mark it NEEDS_INFO, don't assume it works
- HTTP 200 ≠ vulnerable. Empty response ≠ data leak. SPA catch-all ≠ real endpoint.
- Check Content-Type before claiming an endpoint exists (text/html = SPA catch-all, application/json = real API)
- Test with garbage/invalid input first to establish a baseline response

## Workflow Stages

### Stage 0 — Auth Setup
Before any testing, establish authentication:
1. Check if credentials are provided in program.md
2. If yes: authenticate and save session tokens/cookies
3. If no: note which tests are blocked and proceed with unauthenticated testing
4. Document the auth mechanism (cookie/JWT/API key) and how to refresh
5. If HTTP/2 is required for POST requests, note this in program.md "Protocol notes"
Update STATUS.md with auth status.

### Stage 1 — Recon
Map the attack surface. Save to /home/kali/Desktop/bugbounty/bb-workspace/recon/:
- subdomains.md — discovered subdomains and their purpose
- endpoints.md — API endpoints with HTTP methods and auth requirements
- tech-stack.md — frameworks, servers, CDNs, WAFs, databases
- oidc-config.md — if OIDC/OAuth: discovery doc, client IDs, scopes, grant types
Focus on: What returns 401 vs 404? (401 = exists, 404 = doesn't). What Content-Type is returned?
Mark Stage 1 complete in STATUS.md.

### Stage 2 — Hunt
For each finding, create /home/kali/Desktop/bugbounty/bb-workspace/findings/F00X-slug.md using the template.
BEFORE creating a finding file, complete the Reality Check section honestly.
Priority order:
1. Auth bypass / token manipulation
2. IDOR (but ONLY if you can prove data ownership with 2 accounts)
3. Injection (SQLi, XSS, SSTI, SSRF)
4. Business logic flaws (price manipulation, race conditions)
5. Information disclosure (only if sensitive: creds, PII, internal infra)
Mark Stage 2 complete in STATUS.md.

### Stage 3 — Triage
For each finding in /home/kali/Desktop/bugbounty/bb-workspace/findings/ (skip _template.md):
1. Read the finding including its Reality Check
2. Score using /home/kali/Desktop/bugbounty/bb-workspace/triage/_scoring-rubric.md
3. If False Positive Risk ≤ 2: DROP immediately
4. Write scores and decision into the finding file
5. Update STATUS.md findings table
Mark Stage 3 complete.

### Stage 4 — Chain Analysis
Input: findings with decision=CHAIN or SUBMIT.
Rules for chains:
- Every link must be independently tested and working
- Cross-origin chains: verify browser same-origin policy doesn't break it
- Token theft chains: verify token location (HttpOnly cookie? localStorage? memory?)
- Redirect chains: verify the redirect actually happens (not just "the URL is accepted")
Save chain map to /home/kali/Desktop/bugbounty/bb-workspace/chains/chain-map.md.
Mark Stage 4 complete.

### Stage 5 — Draft Reports
For each SUBMIT/CHAIN finding, generate a report.
Save to /home/kali/Desktop/bugbounty/bb-workspace/reports/drafts/F00X-draft.md.
Score report quality. Mark Stage 5 complete.

### Stage 6 — Counter-Path Review
Apply /home/kali/Desktop/bugbounty/bb-workspace/counter-path/_counter-checklist.md to each draft.
Pay special attention to Section 2 (Common False Positives).
Assign verdict. Mark Stage 6 complete.

### Stage 7 — Improve Loop
Loop max 3 times. If still not READY after 3 loops: NEEDS_INFO.
Save final reports to /home/kali/Desktop/bugbounty/bb-workspace/reports/final/F00X-final.md.

## Output When Done
Print summary: Total / Ready / Needs Info / Dropped + final report locations.
```

---

## RESUME PROMPT

```
Read /home/kali/Desktop/bugbounty/bb-workspace/STATUS.md for current progress.
Read all findings in /home/kali/Desktop/bugbounty/bb-workspace/findings/.
Resume from the last incomplete stage. Follow the orchestrator rules above.
```

---

## SINGLE-FINDING REVIEW PROMPT

```
Read /home/kali/Desktop/bugbounty/bb-workspace/findings/[F00X-slug].md
Read /home/kali/Desktop/bugbounty/bb-workspace/counter-path/_counter-checklist.md
Read /home/kali/Desktop/bugbounty/bb-workspace/triage/_scoring-rubric.md

Run a full counter-path review on this finding. Be brutally honest.
Specifically check:
- Is this a false positive? (Section 2 of counter-checklist)
- Does the Reality Check section pass?
- Would a skeptical triager close this as N/A?
Update the finding file with your verdict.
```

---

## PARALLEL SESSION SETUP

**Session A — Recon + Auth**
```
Read /home/kali/Desktop/bugbounty/bb-workspace/program.md
1. Establish authentication (get session cookies/tokens)
2. Map attack surface (subdomains, endpoints, tech stack)
3. Save to /home/kali/Desktop/bugbounty/bb-workspace/recon/
4. Update STATUS.md with auth status and recon progress
```

**Session B — Hunt (Web + API)**
```
Read /home/kali/Desktop/bugbounty/bb-workspace/program.md and recon/ outputs.
Hunt for vulnerabilities. For each finding:
1. Complete the Reality Check BEFORE creating the finding file
2. If Reality Check fails, don't create the file — move on
3. Create /home/kali/Desktop/bugbounty/bb-workspace/findings/F00X-slug.md
```

**Session C — Triage + Counter-Path**
```
Watch /home/kali/Desktop/bugbounty/bb-workspace/findings/ for new files.
For each new finding:
1. Score using the rubric
2. Run counter-path checklist
3. If verdict=DROP, rename file to F00X-slug.DROPPED.md
4. If verdict=READY, generate report to reports/final/
5. Update STATUS.md after each finding
```
