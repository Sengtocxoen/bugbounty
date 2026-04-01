# Triage Scoring Rubric

Use this rubric to score every finding before deciding whether to report, improve, chain, or drop it.

---

## Exploitability (1–5)
| Score | Meaning |
|-------|---------|
| 5 | One-click, no auth, works against any user |
| 4 | Requires low-priv auth or one extra step |
| 3 | Requires some user interaction or specific condition |
| 2 | Complex setup, needs multiple preconditions |
| 1 | Theoretical only, couldn't reproduce reliably |

## Impact (1–5)
| Score | Meaning |
|-------|---------|
| 5 | Full account takeover / RCE / data breach at scale |
| 4 | Partial ATO / significant data exposure / privilege escalation |
| 3 | Limited data access / moderate business impact |
| 2 | Low-sensitivity data / inconvenience to users |
| 1 | Informational / cosmetic / no meaningful impact |

## Confidence (1–5)
| Score | Meaning |
|-------|---------|
| 5 | Fully confirmed with working PoC, data proves the issue |
| 4 | Strong evidence, PoC works but impact partially demonstrated |
| 3 | Behavior observed, PoC incomplete or needs triager verification |
| 2 | Suspicious behavior, no PoC yet |
| 1 | Theoretical based on code/config review only |

## Uniqueness (1–5)
| Score | Meaning |
|-------|---------|
| 5 | Novel chain or logic flaw, unlikely to be known |
| 4 | Uncommon variant of known class |
| 3 | Common class but specific instance on this target |
| 2 | Very common finding, likely already reported |
| 1 | Generic/automated scan finding |

## False Positive Risk (1–5)
| Score | Meaning |
|-------|---------|
| 5 | Definitely real — proved with distinct data from two accounts |
| 4 | Almost certainly real — strong behavioral evidence |
| 3 | Likely real but can't fully prove (e.g., only one test account) |
| 2 | Uncertain — could be server ignoring parameter or SPA catch-all |
| 1 | Probably false positive — same response for valid/invalid/garbage input |

---

## Decision Matrix
| Total Score (out of 25) | Decision |
|-------------------------|----------|
| 21–25 | SUBMIT immediately |
| 16–20 | IMPROVE report then submit |
| 11–15 | CHAIN — try to combine with other findings to raise impact |
| 6–10 | IMPROVE or DROP — needs major work |
| 1–5 | DROP |

---

## Fast-Drop Criteria (skip scoring, drop immediately)
- Explicitly out of scope per program rules
- Requires MitM on HTTPS
- Self-XSS with no escalation path
- Rate limiting on non-auth, non-sensitive endpoint
- Missing security headers with no exploitable impact
- SPF/DMARC issues with no phishing vector
- Same response for your input and garbage input (likely false positive)
- SPA catch-all 200 OK (check Content-Type before claiming endpoint exists)
- "200 OK with empty body" for IDOR without proving data ownership
- Infrastructure error (nginx/CloudFront/ELB) claimed as application vulnerability
- Theoretical chain where any link is unproven

---

## Time-Value Check (before spending more time)
Ask yourself before improving a finding:

| Question | If No → |
|----------|---------|
| Is this finding worth more than $100 in bounty? | Consider dropping, move to next target |
| Can I prove this in under 30 more minutes? | Consider dropping if already spent 1h+ |
| Does the program typically pay for this finding class? | Check their resolved reports if public |
| Am I the first to find this? (check known issues list) | Likely duplicate, deprioritize |
