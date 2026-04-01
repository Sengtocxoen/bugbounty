# Bug Bounty Orchestrator

> Paste this into a fresh Claude Code session to start or resume the workflow.
> The session will read program.md, check STATUS.md, and pick up from the current stage.

---

## START PROMPT (paste into Claude Code)

```
Read F:/bb-workspace/program.md and F:/bb-workspace/STATUS.md.

You are the bug bounty orchestrator. Your job is to run the full workflow below, stage by stage, for the target defined in program.md. After each stage, update STATUS.md.

## Workflow Stages

### Stage 1 — Recon
Use /bb-recon skill. Target: all in-scope domains from program.md.
Save output to F:/bb-workspace/recon/ (subdomains.md, endpoints.md, tech-stack.md).
Mark Stage 1 complete in STATUS.md when done.

### Stage 2 — Hunt
Run these in parallel (open 3 sessions or run sequentially):
- /bb-webapp — web application testing
- /bb-api — API security testing  
- /bb-domain — domain/infra hunting
For each finding discovered, create a finding file at F:/bb-workspace/findings/F00X-slug.md using the template at F:/bb-workspace/findings/_template.md.
Mark Stage 2 complete in STATUS.md when done.

### Stage 3 — Triage
For each finding file in F:/bb-workspace/findings/ (skip _template.md):
1. Read the finding
2. Read F:/bb-workspace/triage/_scoring-rubric.md
3. Score it (Exploitability, Impact, Confidence, Uniqueness)
4. Write the scores and decision into the finding file's Triage Scores section
5. Update the Findings Summary table in STATUS.md
Drop any findings with decision=DROP. Flag CHAIN findings.
Mark Stage 3 complete in STATUS.md.

### Stage 4 — Chain Analysis
Use /bb-chain skill.
Input: all findings with decision=CHAIN or SUBMIT from triage.
Look for compound chains that increase severity.
Save chain map to F:/bb-workspace/chains/chain-map.md.
Update any chained finding files with chain references.
Mark Stage 4 complete in STATUS.md.

### Stage 5 — Draft Reports
For each finding with decision=SUBMIT or CHAIN:
Use /bb-report skill to generate a platform-ready report.
Save draft to F:/bb-workspace/reports/drafts/F00X-draft.md.
Score the report quality (Clarity, Reproducibility, Impact articulation, Evidence quality).
Write scores into the finding file's Report Quality Score section.
Mark Stage 5 complete in STATUS.md.

### Stage 6 — Counter-Path Review
For each draft report:
1. Read F:/bb-workspace/counter-path/_counter-checklist.md
2. Apply every checklist item to the finding
3. Write results into the finding file's Counter-Path Review section
4. Assign verdict: READY / NEEDS_IMPROVEMENT / NEEDS_INFO / DROP
5. If NEEDS_INFO: add specific question to STATUS.md "Blocked / Needs Human Input" section
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
- Save final report to F:/bb-workspace/reports/final/F00X-final.md
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
- Final reports location: F:/bb-workspace/reports/final/
```

---

## RESUME PROMPT (if session was interrupted)

```
Read F:/bb-workspace/STATUS.md to see current stage and progress.
Read all finding files in F:/bb-workspace/findings/ to understand current state.
Resume the workflow from the last incomplete stage.
Follow the same stage instructions as in the full orchestrator prompt.
```

---

## SINGLE-FINDING REVIEW PROMPT

```
Read F:/bb-workspace/findings/[F00X-slug].md
Read F:/bb-workspace/counter-path/_counter-checklist.md
Read F:/bb-workspace/triage/_scoring-rubric.md

Run a full counter-path review on this finding.
Update the Counter-Path section in the finding file.
If verdict is NEEDS_IMPROVEMENT, list exactly what to fix.
If verdict is NEEDS_INFO, write the specific question to ask the user.
If verdict is READY, generate the final report and save to F:/bb-workspace/reports/final/[F00X]-final.md
```

---

## PARALLEL SESSION SETUP

For maximum speed, run these 3 sessions simultaneously:

**Session A — Recon + Domain**
```
Read F:/bb-workspace/program.md
Run /bb-recon and /bb-domain on all in-scope targets.
Save all output to F:/bb-workspace/recon/
When done, append to STATUS.md session log.
```

**Session B — Web + API Hunt**
```
Read F:/bb-workspace/program.md and F:/bb-workspace/recon/ outputs.
Run /bb-webapp and /bb-api.
For each finding, create F:/bb-workspace/findings/F00X-slug.md using the template.
```

**Session C — Monitor + Triage**
```
Watch F:/bb-workspace/findings/ for new files.
As Session B creates finding files, triage them immediately using _scoring-rubric.md.
Update STATUS.md findings table after each triage.
```
