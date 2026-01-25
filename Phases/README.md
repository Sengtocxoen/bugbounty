# Bug Bounty Phases

This directory organizes the bug bounty hunting workflow into four distinct phases. Each phase builds upon the previous, creating a systematic approach to finding vulnerabilities.

---

## Phase Overview

```
+------------------+     +------------------+     +------------------+     +------------------+
|                  |     |                  |     |                  |     |                  |
|  RECONNAISSANCE  | --> |     ANALYSIS     | --> |  EXPLOITATION    | --> |    REPORTING     |
|                  |     |                  |     |                  |     |                  |
+------------------+     +------------------+     +------------------+     +------------------+
| - Subdomain enum |     | - Attack surface |     | - Vuln testing   |     | - Documentation  |
| - Asset discovery|     | - Workflow mapping|    | - PoC development|     | - Submission     |
| - Tech detection |     | - Entry points   |     | - Impact verify  |     | - Follow-up      |
+------------------+     +------------------+     +------------------+     +------------------+
```

---

## Phase Descriptions

### [Phase 1: Reconnaissance](Phase1_Reconnaissance.md)
**Goal:** Discover and enumerate all in-scope assets

- Subdomain enumeration (passive + active)
- DNS resolution and filtering
- Technology stack identification
- Endpoint discovery
- Historical data gathering

**Tools:** subfinder, amass, httpx, waybackurls, gau

---

### [Phase 2: Analysis](Phase2_Analysis.md)
**Goal:** Map attack surface and identify potential entry points

- Attack surface mapping
- Workflow analysis
- Authentication flow review
- API endpoint cataloging
- Feature identification (SSRF, IDOR candidates)

**Output:** Prioritized list of testing targets

---

### [Phase 3: Exploitation](Phase3_Exploitation.md)
**Goal:** Test vulnerabilities and develop proof of concepts

- Vulnerability testing by category:
  - IDOR
  - SSRF
  - Business Logic
  - Injection (SQLi, XSS, etc.)
  - Subdomain Takeover
- PoC development
- Impact verification

**Output:** Verified vulnerabilities with PoC

---

### [Phase 4: Reporting](Phase4_Reporting.md)
**Goal:** Document and submit findings professionally

- Report writing
- Evidence collection
- Impact assessment
- Submission
- Retesting after fixes

**Output:** High-quality vulnerability reports

---

## Workflow Integration

```
                                    +-----------------+
                                    |  New Program    |
                                    |  or Target      |
                                    +--------+--------+
                                             |
                                             v
+----------------------------------------------------------------------------------------+
|                                                                                        |
|  +----------------+    +----------------+    +----------------+    +----------------+  |
|  |                |    |                |    |                |    |                |  |
|  |    PHASE 1     |    |    PHASE 2     |    |    PHASE 3     |    |    PHASE 4     |  |
|  |                |    |                |    |                |    |                |  |
|  | Reconnaissance |--->|    Analysis    |--->|  Exploitation  |--->|   Reporting    |  |
|  |                |    |                |    |                |    |                |  |
|  +-------+--------+    +-------+--------+    +-------+--------+    +-------+--------+  |
|          |                     |                     |                     |           |
|          v                     v                     v                     v           |
|  +----------------+    +----------------+    +----------------+    +----------------+  |
|  | Subdomains     |    | Attack Surface |    | Verified Vulns |    | Submitted      |  |
|  | Endpoints      |    | Entry Points   |    | PoCs           |    | Reports        |  |
|  | Tech Stack     |    | Targets List   |    | Impact Proof   |    | Bounties       |  |
|  +----------------+    +----------------+    +----------------+    +----------------+  |
|                                                                                        |
+----------------------------------------------------------------------------------------+
                                             |
                                             v
                                    +-----------------+
                                    |  Iterate &      |
                                    |  Monitor        |
                                    +-----------------+
```

---

## Phase-Specific Directories

Each program directory (Amazon/, Shopify/) can contain phase-specific subdirectories:

```
Amazon/
├── Overview.md
├── scopes_amazon.csv
├── Phase1_Recon/
│   ├── subdomains/
│   ├── endpoints/
│   └── tech_stack/
├── Phase2_Analysis/
│   ├── attack_surface.md
│   └── targets.md
├── Phase3_Testing/
│   ├── findings/
│   └── poc/
└── Phase4_Reports/
    ├── submitted/
    └── drafts/
```

---

## Quick Start

### 1. New Target Setup
```bash
# Read program rules first!
cat Amazon/Overview.md

# Start Phase 1
python tools/wiz_recon.py amazon.com -p amazon -u yourh1username
```

### 2. Follow the Phases
```
Phase 1 -> Get subdomains and endpoints
Phase 2 -> Identify high-value targets
Phase 3 -> Test for vulnerabilities
Phase 4 -> Report findings
```

### 3. Iterate
- New subdomains discovered? -> Back to Phase 2
- Fix deployed? -> Retest in Phase 3
- New feature released? -> Start from Phase 1

---

## Key Principles

1. **Sequential but Iterative** - Follow phases in order, but cycle back as needed
2. **Document Everything** - Each phase produces artifacts for the next
3. **Stay In Scope** - Verify scope at every phase
4. **Quality Over Speed** - Thorough testing beats rushed scanning
5. **Continuous Learning** - Each cycle improves your methodology

---

## Related Documents

- [Vulnerabilities That Matter](../Vulnerabilities_That_Matter.md) - Key vulnerability types
- [Reconnaissance Guide](../Reconnaissance_Guide.md) - Detailed recon techniques
- [Testing Strategy](../Testing_Strategy.md) - Program-specific testing
- [Quick Reference Checklist](../Quick_Reference_Checklist.md) - Pre-testing checklist
