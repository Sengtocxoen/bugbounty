# Bug Bounty Scanner — Execution Layer Stack

> How the scanner works from bottom to top — from bare metal to AI-driven results.

---

## The Pre-Thinking Stack

Think of the system as layers. Bottom = deepest infrastructure, Top = closest to AI reasoning.

```
Layer 5: Orchestration       ← controls WHEN scanner runs + what it receives
Layer 4: System Prompt       ← controls HOW scanner reasons
Layer 3: Context Assembly    ← controls WHAT scanner knows at start
Layer 2: Tool Exposure       ← controls WHAT scanner can do
Layer 1.5: Burp Suite Pro    ← intercept + scan + OOB (NEW)
Layer 1: Environment         ← controls WHAT actually executes
─────────────────────────────────────────────────
                AI Thinking
─────────────────────────────────────────────────
              Results / Actions
```

---

## Layer 1 — Environment (Deepest)

The runtime the scanner lives in:

- Pre-installed tools: `nmap`, `nuclei`, `subfinder`, `httpx`, `ffuf`, `katana`, etc.
- Network access configured (can reach target)
- File system: `./configs/`, `./deep_scan_results/`, `./tools/`
- Python 3.10+ with all dependencies (`requirements.txt`)
- External binaries managed via `install_all_tools.sh`

> If this layer is wrong, nothing above it works.

---

## Layer 1.5 — Burp Suite Pro (NEW)

The interception layer between the scanner and the target:

```
scanner.py → HTTP Client → Chromium [proxy=127.0.0.1:8080]
                                ↕
                          Burp Suite Pro        ← THIS LAYER
                   (intercept + scan + log + Collaborator)
                                ↕
                           Target App
```

### What Burp Adds

**Passive (always-on):**
- Every request flows through Burp — full HTTP history captured
- Burp's passive scanner flags issues on traffic it sees (missing headers, cookie flags, info leakage)
- No extra action needed — runs automatically

**Active (scanner-triggered):**
- Scanner calls Burp REST API to trigger active scans
- Burp runs its own fuzzer/scanner independently
- Dual coverage: custom logic + Burp brute force in parallel

**Burp Collaborator — killer feature for blind vulns:**
- SSRF, blind SQLi, XXE, DNS rebinding — vulnerabilities with no visible HTTP response
- Burp injects unique callback URLs (`xyz.burpcollaborator.net`) into payloads
- If the server makes an out-of-band DNS/HTTP call → Burp catches it → confirms the vuln
- Without Collaborator, blind vulns are nearly invisible to automated tools

### Burp REST API Integration

```
┌──────────────────────────────────────┐
│  Burp REST API (port 1337)           │
│                                      │
│  GET  /scan-issues    ← query        │
│  POST /scan           ← trigger      │
│  GET  /proxy/history  ← replay       │
│  GET  /collaborator   ← OOB checks   │
└──────────────────────────────────────┘
```

### Headless Deployment

```bash
java -jar burpsuite_pro.jar \
  --headless \
  --config-file=burp-config.json \
  --user-config-file=burp-user.json
```

Configured via `scan_config.yaml`:
```yaml
burp_suite:
  enabled: true
  jar_path: "/path/to/burpsuite_pro.jar"
  api_port: 1337
  auto_launch: true
```

Implemented in: [`burp_wrapper.py`](file:///f:/work/BugBounty/bugbounty/bugbounty/tools/scanners/burp_wrapper.py)

---

## Layer 2 — Tool Exposure

What the scanner can do — the Python modules and external binaries available:

- **60+ Python modules** across 7 directories (see [Architechture.md](file:///f:/work/BugBounty/bugbounty/bugbounty/Architechture.md))
- **12+ external binaries**: Nuclei, Subfinder, Amass, HTTPX, FFuf, Katana, Dalfox, Arjun, Interactsh, Naabu, Trufflehog, Kiterunner
- **Burp Suite Pro** REST API (4 endpoints)

> Tool descriptions matter. Rich descriptions = better tool selection by the orchestrator.

---

## Layer 3 — Context Assembly (Pre-prompt)

What the scanner knows before it starts scanning:

- Target domains + subdomains from `scan_config.yaml`
- Program-specific rules (rate limits, custom headers, scope)
- Tech stack detected via `tech_detection.py` (framework, DB, auth type)
- Prior recon results (subdomain lists, endpoint inventory)
- **Burp scan results** fed back as context for deeper scans
- Known vulnerability patterns for the detected stack

> This is the briefing before the mission. Quality here determines targeted vs generic scans.

---

## Layer 4 — System Prompt / Instructions

The rules the scanner follows — defined in `Agent.md` and `scan_config.yaml`:

- **Goal**: Find Critical/High severity bugs (SSRF, IDOR, RCE)
- **Methodology**: Deep-Dive — bypass WAFs, discover hidden cloud assets, chain vulns
- **Output**: Every finding logged with reproducibility snippet (curl command)
- **Constraints**: Respect rate limits, scope, safety rules
- **Verification**: Zero false positives — every finding goes through verifiers

---

## Layer 5 — Orchestration (Workflow)

How the scanner chains phases and manages execution:

- **13 scan modes** dispatched from `scanner.py`
- **Phase pipeline**: Discovery → Analysis → Scanning → Verification → Reporting
- **Parallel execution**: Multiple engines run concurrently (`run_all_mode`)
- **Continuous monitoring**: 24/7 mode with change detection
- **State management**: Graceful shutdown via SIGINT handler
- **Burp feedback loop**: Post-scan Burp auto-launch, findings merged back

---

## The Feedback Loop

This is what makes the architecture powerful — Burp doesn't just sit passively:

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  Scanner (Layer 5)                                       │
│    │                                                     │
│    ├── Run discovery/analysis/scanning phases            │
│    │      ↓                                              │
│    │   All HTTP traffic flows through Burp (Layer 1.5)   │
│    │      ↓                                              │
│    ├── Query Burp for passive findings (Layer 3 feedback)│
│    ├── Trigger Burp active scans on key endpoints        │
│    ├── Poll Collaborator for OOB callbacks               │
│    │      ↓                                              │
│    └── Merge Burp findings + custom findings → Report    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### What This Catches That the Scanner Alone Misses

| Gap | How Burp Fills It |
|:----|:------------------|
| Blind SQLi / blind SSRF | Collaborator OOB callbacks |
| Response-level issues | Burp catches header/response issues automatically |
| Coverage gaps | Burp fuzzes every parameter it sees |
| Passive leakage | API keys, stack traces, verbose errors — Burp logs everything |

---

## Priority Order for Setup

1. **Layer 1** first — get the environment right (tools + network)
2. **Layer 4** next — system prompt is highest leverage
3. **Layer 2** — ensure all tools are installed and accessible
4. **Layer 1.5** — Burp Suite Pro configuration
5. **Layer 3** — automate context assembly (tech detection, endpoint crawling)
6. **Layer 5** last — orchestration complexity only pays off once the above work