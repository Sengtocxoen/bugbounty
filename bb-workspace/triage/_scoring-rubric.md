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
| 5 | Fully confirmed with working PoC |
| 4 | Strong evidence, PoC partially works |
| 3 | Behavior observed, PoC incomplete |
| 2 | Suspicious behavior, no PoC |
| 1 | Theoretical based on code/config review |

## Uniqueness (1–5)
| Score | Meaning |
|-------|---------|
| 5 | Novel chain or logic flaw, unlikely to be known |
| 4 | Uncommon variant of known class |
| 3 | Common class but specific instance |
| 2 | Very common finding, likely already reported |
| 1 | Generic/automated scan finding |

---

## Decision Matrix
| Total Score | Decision |
|-------------|----------|
| 17–20 | SUBMIT immediately |
| 13–16 | IMPROVE report then submit |
| 9–12 | CHAIN — try to combine with other findings to raise impact |
| 5–8 | IMPROVE or DROP — needs major work |
| 1–4 | DROP |

---

## Fast-Drop Criteria (skip scoring, drop immediately)
- Explicitly out of scope
- Requires MitM on HTTPS
- Self-XSS with no escalation path
- Rate limiting on non-auth, non-sensitive endpoint
- Missing security headers with no exploitable impact
- SPF/DMARC issues with no phishing vector
