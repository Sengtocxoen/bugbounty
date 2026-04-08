# Bug Bounty Workspace — Claude Code Context

## Skill to Use
The primary skill for all work in this workspace is **SKILL_BB.md** located at `F:/bugbounty/SKILL_BB.md`.

Invoke it via the `/bb` command. Sub-skills available:
- `/bb-recon` — reconnaissance pipeline
- `/bb-domain` — domain & DNS hunt
- `/bb-webapp` — web application hunt
- `/bb-api` — API security hunt
- `/bb-chain` — vulnerability chaining & escalation
- `/bb-report` — report writer

## Workspace Root
`F:/bugbounty/bb-workspace/`

## Cognitive Operating System (apply before every action)
Before invoking any tool or producing any output, apply the 4-step reasoning chain from SKILL_BB.md:
1. **State & Flow Modeling** — map trust boundaries, Source → Propagator → Sanitizer → Sink
2. **Empirical Grounding** — zero assumptions; read actual responses and tool output before drawing conclusions
3. **Adaptive Self-Correction** — diagnose failures before retrying; pivot strategy when an approach is exhausted
4. **Impact Control** — evaluate destructive risk before every state-changing action; halt and ask if scope is unclear

Also apply the **Universal Tool Orchestration Policy** (SKILL_BB.md §UNIVERSAL TOOL ORCHESTRATION POLICY):
- Validate syntax/payloads before firing at the target
- Pull knowledge on-demand (demand-driven), don't assume
- Truth comes from logs/output only — silent = ambiguous
- Set resource limits; clean up all temp artifacts after use

## Workflow Stages
```
program.md filled
      ↓
Stage 1: Recon      → recon/subdomains.md, endpoints.md, tech-stack.md
      ↓
Stage 2: Hunt       → findings/F00X-slug.md (one file per vuln)
      ↓
Stage 3: Triage     → score each finding → SUBMIT / IMPROVE / CHAIN / DROP
      ↓
Stage 4: Chain      → chains/chain-map.md (AI Planning format)
      ↓
Stage 5: Reports    → reports/drafts/ → reports/final/
      ↓
Stage 6: Counter-Path → devil's advocate review → READY / NEEDS_IMPROVEMENT / NEEDS_INFO
      ↓
Stage 7: Improve Loop → max 3 loops → FINAL or NEEDS_INFO
```

## Key Files
| File | Purpose |
|------|---------|
| `program.md` | Target scope, credentials, tech stack — fill before any stage |
| `STATUS.md` | Live stage tracker — update after every stage |
| `findings/_template.md` | Copy for each new finding |
| `triage/_scoring-rubric.md` | Scoring criteria for triage decisions |
| `counter-path/_counter-checklist.md` | Devil's advocate validation checklist |
| `chains/_chain-template.md` | AI Planning chain map template |
| `improve/_improve-prompt.md` | Improve loop instructions |

## Program Context Loading
SKILL_BB.md Step 0 auto-loads program context. Point it at `program.md`:
```
/bb [target-from-program.md]
```
Or use the full orchestrator prompt from `ORCHESTRATOR.md`.

## Finding Taint Map Requirement
Every finding file MUST include a completed Taint Map before triage:
- **Source**: Where does attacker-controlled data enter?
- **Propagator**: How does it flow through the system?
- **Sanitizer**: What validation exists — and can it be bypassed?
- **Sink**: Where does it land (DB query, `eval()`, URL fetcher, file write)?

Findings without a completed Taint Map are automatically flagged as Confidence ≤ 3 in triage.

## Exploit Chain Format
Use the AI Planning model from SKILL_BB.md for all chain entries:
```
Action: [Vulnerability Name]
  Preconditions: [States that must be true]
  Effects:       [New states after execution]
  Chains into:   [Higher-tier action this enables]
```

## Report Quality Threshold
**16/20 minimum** before marking FINAL:
- Clarity: 5 | Reproducibility: 5 | Impact articulation: 5 | Evidence quality: 5
