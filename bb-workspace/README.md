# BB Workspace — Bug Bounty Workflow System

## Quick Start

1. Copy this entire `bb-workspace/` folder for each new program
2. Fill in `program.md` with your target's scope, rules, creds, and previous reports
3. Open Claude Code and paste the **START PROMPT** from `ORCHESTRATOR.md`
4. Watch it run. Check `STATUS.md` for live progress.
5. If it gets stuck (NEEDS_INFO), answer the question in STATUS.md and resume with the **RESUME PROMPT**

---

## Directory Layout

```
bb-workspace/
├── program.md              ← START HERE — fill in your target
├── ORCHESTRATOR.md         ← Prompts for each session type
├── STATUS.md               ← Live progress tracker
├── README.md               ← This file
│
├── recon/                  ← Stage 1 output
│   ├── subdomains.md
│   ├── endpoints.md
│   ├── tech-stack.md
│   └── oidc-config.md
├── findings/               ← One file per vulnerability found
│   └── _template.md        ← Copy this for each new finding
├── triage/
│   └── _scoring-rubric.md  ← Scoring system (out of 25 with FP risk)
├── chains/
│   └── chain-map.md        ← How findings combine
├── reports/
│   ├── drafts/             ← Work-in-progress reports
│   └── final/              ← SUBMIT THESE to the platform
├── counter-path/
│   └── _counter-checklist.md  ← Devil's advocate (includes false positive checks)
└── improve/
    └── _improve-prompt.md  ← How to fix weak findings
```

---

## Workflow

```
program.md filled
      ↓
Stage 0: Auth Setup (get session, document auth mechanism)
      ↓
Stage 1: Recon (subdomains, endpoints, tech stack, OIDC config)
      ↓
Stage 2: Hunt → findings/F00X.md created (with Reality Check filled)
      ↓
Stage 3: Triage (score each finding → SUBMIT / IMPROVE / CHAIN / DROP)
      ↓
Stage 4: Chain Analysis (combine findings, TEST every link)
      ↓
Stage 5: Draft Reports → reports/drafts/
      ↓
Stage 6: Counter-Path Review (devil's advocate + false positive checks)
      ↓
Stage 7: Improve Loop ← max 3 loops, then NEEDS_INFO
      ↓
reports/final/ ← submit these
```

---

## Key Rules (learned from real testing)

### Before Creating a Finding
- [ ] Complete the **Reality Check** section in the template HONESTLY
- [ ] Test with garbage/invalid input to establish baseline
- [ ] Check Content-Type (text/html = SPA catch-all, NOT a real API endpoint)
- [ ] Check if the finding is in "Known Issues" or "Previous Reports"

### IDOR Proof Requirements
- **200 OK for any ID ≠ IDOR.** The server may ignore the parameter entirely.
- **Empty response for other IDs ≠ data leak.** It might be YOUR empty data.
- **PROOF = Account A's token + Account B's ID → Account B's DISTINCT data**

### Chain Requirements
- Every link must be independently tested
- Cross-origin restrictions must be verified (not assumed away)
- Token theft requires knowing WHERE the token is stored (cookie vs localStorage vs memory)

### Time Management
- Spend max 2 hours on recon before starting to hunt
- If a finding can't be proven in 30 more minutes, move on
- Don't improve a finding more than 3 times — either it's ready or drop it
- Check the bounty range: don't spend 4 hours on a $50 finding

---

## Parallel Sessions (fastest mode)

| Session | Role | Prompt |
|---------|------|--------|
| A | Recon + Auth setup | PARALLEL SESSION SETUP → Session A |
| B | Hunt (Web + API) | PARALLEL SESSION SETUP → Session B |
| C | Triage + Counter-path | PARALLEL SESSION SETUP → Session C |

---

## Stopping Conditions

| Status | Meaning |
|--------|---------|
| `FINAL` | Report is ready to copy-paste into the platform |
| `NEEDS_INFO` | Blocked — check STATUS.md for what's needed |
| `DROP` | Finding did not survive scrutiny — move on |

---

## Quality Thresholds

- **Triage score**: 16/25 minimum to proceed to report (with FP Risk ≥ 3)
- **Report quality**: 16/20 minimum before marking FINAL
- **Max improve loops**: 3 per finding
