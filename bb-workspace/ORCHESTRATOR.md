# Bug Bounty Orchestrator

> Paste this into a fresh Claude Code session to start or resume the workflow.
> The session will read program.md, check STATUS.md, and pick up from the current stage.

**Workspace path:** `F:/bugbounty/bb-workspace/`
**Primary skill:** `F:/bugbounty/SKILL_BB.md` — invoked via `/bb`

---

## START PROMPT (paste into Claude Code)

```
Read F:/bugbounty/bb-workspace/program.md and F:/bugbounty/bb-workspace/STATUS.md.
Read F:/bugbounty/SKILL_BB.md to load the full skill context.

You are the bug bounty orchestrator. Before every action, apply the 4-step reasoning
chain from SKILL_BB.md (State & Flow Modeling → Empirical Grounding → Adaptive
Self-Correction → Impact Control) and the Universal Tool Orchestration Policy.

Run the full workflow below, stage by stage, for the target defined in program.md.
After each stage, update STATUS.md.

## Workflow Stages

### Stage 1 — Recon
Use /bb-recon and /bb-domain skills. Target: all in-scope domains from program.md.
Copy F:/bugbounty/bb-workspace/recon/_template.md to recon/[target]-recon.md and fill it.
Save raw outputs to recon/ (subdomains-raw.txt, live-hosts.txt, endpoints-raw.txt).
Mark Stage 1 complete in STATUS.md when done.

### Stage 2 — Hunt
Run these in parallel (open 3 sessions or run sequentially):
- /bb-webapp — web application testing
- /bb-api — API security testing
- /bb-domain — domain/infra hunting
For each finding discovered, copy F:/bugbounty/bb-workspace/findings/_template.md
to findings/F00X-slug.md. REQUIRED: fill the Taint Map section before moving on.
Mark Stage 2 complete in STATUS.md when done.

### Stage 3 — Triage
For each finding file in F:/bugbounty/bb-workspace/findings/ (skip _template.md):
1. Read the finding — verify Taint Map is complete (if not, fill it or flag NEEDS_INFO)
2. Read F:/bugbounty/bb-workspace/triage/_scoring-rubric.md
3. Score it (Exploitability, Impact, Confidence, Uniqueness)
4. Write scores and decision into the finding file's Triage Scores section
5. Update the Findings Summary table in STATUS.md
Drop any findings with decision=DROP. Flag CHAIN findings.
Mark Stage 3 complete in STATUS.md.

### Stage 4 — Chain Analysis
Use /bb-chain skill.
Input: all findings with decision=CHAIN or SUBMIT from triage.
Look for compound chains that increase severity using the AI Planning model:
  Action → Preconditions → Effects → Chains into
Copy F:/bugbounty/bb-workspace/chains/_chain-template.md to chains/chain-map.md and fill it.
Update any chained finding files with chain references.
Mark Stage 4 complete in STATUS.md.

### Stage 5 — Draft Reports
For each finding with decision=SUBMIT or CHAIN:
Use /bb-report skill to generate a platform-ready report.
Save draft to F:/bugbounty/bb-workspace/reports/drafts/F00X-draft.md.
Score the report quality (Clarity, Reproducibility, Impact articulation, Evidence quality).
Write scores into the finding file's Report Quality Score section.
Mark Stage 5 complete in STATUS.md.

### Stage 6 — Counter-Path Review
For each draft report:
1. Read F:/bugbounty/bb-workspace/counter-path/_counter-checklist.md
2. Start with Section 0 (Empirical Grounding) — if any Section 0 item fails, fix it before continuing
3. Apply all remaining checklist sections
4. Write results into the finding file's Counter-Path Review section
5. Assign verdict: READY / NEEDS_IMPROVEMENT / NEEDS_INFO / DROP
6. If NEEDS_INFO: add specific question to STATUS.md "Blocked / Needs Human Input" section
Mark Stage 6 complete in STATUS.md.

### Stage 7 — Improve Loop
For each finding with verdict=NEEDS_IMPROVEMENT:
- Address every weak point identified in counter-path review
- Re-run /bb-report to regenerate the report
- Re-score report quality
- Re-run counter-path checklist
- Increment loop counter in finding file
- If loop count >= 3 and still not READY: escalate to NEEDS_INFO

For each finding with verdict=READY:
- Save final report to F:/bugbounty/bb-workspace/reports/final/F00X-final.md
- Mark as FINAL in STATUS.md

Loop until all findings are either FINAL, NEEDS_INFO, or DROP.

## Loop Termination
The workflow is complete when:
- All findings in STATUS.md have status = FINAL, NEEDS_INFO, or DROP
- No finding has status = DRAFT or IMPROVED

## Output When Done
Print a summary:
- Total findings: X
- Ready to submit: X (list IDs + titles)
- Needs human input: X (list IDs + what's needed)
- Dropped: X
- Final reports location: F:/bugbounty/bb-workspace/reports/final/
```

---

## RESUME PROMPT (if session was interrupted)

```
Read F:/bugbounty/bb-workspace/STATUS.md to see current stage and progress.
Read all finding files in F:/bugbounty/bb-workspace/findings/ to understand current state.
Read F:/bugbounty/SKILL_BB.md to reload skill context.
Resume the workflow from the last incomplete stage.
Follow the same stage instructions as in the full orchestrator prompt.
```

---

## SINGLE-FINDING REVIEW PROMPT

```
Read F:/bugbounty/bb-workspace/findings/[F00X-slug].md
Read F:/bugbounty/bb-workspace/counter-path/_counter-checklist.md
Read F:/bugbounty/bb-workspace/triage/_scoring-rubric.md
Read F:/bugbounty/SKILL_BB.md (Workflow F — Chain & Escalate)

First verify the Taint Map is complete. If not, fill it from the evidence in the finding.
Run a full counter-path review starting with Section 0 (Empirical Grounding).
Update the Counter-Path section in the finding file.
If verdict is NEEDS_IMPROVEMENT, list exactly what to fix.
If verdict is NEEDS_INFO, write the specific question to ask the user.
If verdict is READY, generate the final report and save to:
  F:/bugbounty/bb-workspace/reports/final/[F00X]-final.md
```

---

## PARALLEL SESSION SETUP

For maximum speed, run these 3 sessions simultaneously:

**Session A — Recon + Domain**
```
Read F:/bugbounty/bb-workspace/program.md
Read F:/bugbounty/SKILL_BB.md (Workflows B and E)
Run /bb-recon and /bb-domain on all in-scope targets.
Fill F:/bugbounty/bb-workspace/recon/_template.md → save as recon/[target]-recon.md
When done, append to STATUS.md session log.
```

**Session B — Web + API Hunt**
```
Read F:/bugbounty/bb-workspace/program.md
Read F:/bugbounty/bb-workspace/recon/[target]-recon.md
Read F:/bugbounty/SKILL_BB.md (Workflows C, D, H, I)
Run /bb-webapp and /bb-api.
For each finding: copy findings/_template.md → findings/F00X-slug.md
REQUIRED: fill the Taint Map section in every finding file before saving.
```

**Session C — Triage Monitor**
```
Read F:/bugbounty/bb-workspace/triage/_scoring-rubric.md
Watch F:/bugbounty/bb-workspace/findings/ for new files.
As Session B creates finding files:
  1. Verify Taint Map is filled (flag NEEDS_INFO if missing)
  2. Score using rubric
  3. Write triage decision into the finding file
  4. Update STATUS.md findings table
```
