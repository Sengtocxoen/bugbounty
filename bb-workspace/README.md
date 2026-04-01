# BB Workspace — Bug Bounty Workflow System

## Quick Start

1. Fill in `program.md` with your target's scope, rules, and credentials
2. Open Claude Code and paste the **START PROMPT** from `ORCHESTRATOR.md`
3. Watch it run. Check `STATUS.md` for live progress.
4. If it gets stuck (NEEDS_INFO), answer the question in STATUS.md and resume with the **RESUME PROMPT**

---

## Directory Layout

```
bb-workspace/
├── program.md              ← START HERE — fill in your target
├── ORCHESTRATOR.md         ← Prompts for each session type
├── STATUS.md               ← Live progress tracker
├── README.md               ← This file
│
├── recon/                  ← Stage 1 output (subdomains, endpoints, tech)
├── findings/               ← One file per vulnerability found
│   └── _template.md        ← Copy this for each new finding
├── triage/                 ← Scoring rubric and triage log
├── chains/                 ← Vulnerability chain maps
├── reports/
│   ├── drafts/             ← Work-in-progress reports
│   └── final/              ← SUBMIT THESE
├── counter-path/           ← Devil's advocate checklist
└── improve/                ← Improvement loop prompts
```

---

## Workflow Overview

```
program.md filled
      ↓
Stage 1: Recon (/bb-recon, /bb-domain)
      ↓
Stage 2: Hunt (/bb-webapp, /bb-api) → findings/F00X.md created
      ↓
Stage 3: Triage (score each finding → SUBMIT / IMPROVE / CHAIN / DROP)
      ↓
Stage 4: Chain Analysis (/bb-chain → combine low findings into high)
      ↓
Stage 5: Draft Reports (/bb-report → reports/drafts/)
      ↓
Stage 6: Counter-Path Review (devil's advocate → READY / NEEDS_IMPROVEMENT / NEEDS_INFO)
      ↓
Stage 7: Improve Loop ← loops back to Stage 6 until READY or loop limit hit
      ↓
reports/final/ ← submit these
```

---

## Parallel Sessions (fastest mode)

| Session | What it does | Prompt to use |
|---------|-------------|---------------|
| A | Recon + Domain | PARALLEL SESSION SETUP → Session A |
| B | Web + API Hunt | PARALLEL SESSION SETUP → Session B |
| C | Triage monitor | PARALLEL SESSION SETUP → Session C |
| D | Counter-path + improve | SINGLE-FINDING REVIEW PROMPT |

---

## Stopping Conditions

| Status | Meaning |
|--------|---------|
| `FINAL` | Report is ready to copy-paste into the platform |
| `NEEDS_INFO` | You need to provide something (answer is in STATUS.md) |
| `DROP` | Finding did not survive scrutiny — not worth submitting |

---

## Loop Limit

Each finding loops max **3 times** through counter-path → improve.
After 3 loops without READY verdict, it moves to NEEDS_INFO and waits for you.

---

## Report Quality Threshold

A finding needs **16/20** report quality score before it's marked FINAL.
- Clarity: 5
- Reproducibility: 5
- Impact articulation: 5
- Evidence quality: 5
