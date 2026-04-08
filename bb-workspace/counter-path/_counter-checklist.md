# Counter-Path Review Checklist

> Devil's advocate review. For each finding, challenge every assumption before submitting.
> Goal: find what a skeptical triager would reject, then fix it preemptively.

---

## Section 0 — Empirical Grounding (SKILL_BB.md Step 2 — run this first)
These checks block the review if failed. A finding with hallucinated evidence wastes everyone's time.

- [ ] **Is every claim backed by actual tool output or HTTP response?** (No "this probably works" or "the code looks like it could...")
- [ ] **Is the Taint Map completed?** (Source → Propagator → Sanitizer → Sink — all four fields filled, not left blank)
- [ ] **Was the Sanitizer actually tested?** (Did you confirm the filter can be bypassed, or did you just assume it's absent?)
- [ ] **Is the PoC derived from a real test run?** (Not constructed from what "should" happen — mark any unverified steps as `[NOT YET VERIFIED]`)
- [ ] **Were all tools run with their actual output captured?** (No silent failures assumed to be successes)

---

## Section 1 — Validity Challenges
Ask these about every finding:

- [ ] **Can a WAF/filter block this in production?** (Did you test against the real prod environment or just staging?)
- [ ] **Is this actually exploitable, or just observable?** (Can you demonstrate real impact beyond "the field reflects input"?)
- [ ] **Does exploiting this require a precondition that's unlikely?** (e.g., specific user role, specific account state, race condition timing)
- [ ] **Is this actually by design?** (Could this be an intentional feature? Check docs/changelog.)
- [ ] **Is the target in scope?** (Re-check program.md scope. Check for CDN/third-party exclusions.)
- [ ] **Is this already patched?** (Re-test on fresh session. Clear cookies/cache.)
- [ ] **Is your PoC reproducible by someone else?** (Would a triager be able to follow your steps exactly?)

---

## Section 2 — Impact Challenges
- [ ] **Is the impact you claimed the real worst-case, or did you understate it?** (Think: what can a motivated attacker do with this?)
- [ ] **Is the impact you claimed realistic, or hypothetical?** (e.g., "attacker could read all user data" — can they really, or just their own?)
- [ ] **Does the impact require additional findings to realize?** (If so, document the chain.)
- [ ] **What's the blast radius?** (One user? All users? Specific role? Admin only?)

---

## Section 3 — Report Quality Challenges
- [ ] **Is the title specific enough?** (Bad: "XSS in login". Good: "Stored XSS in profile bio field allows account takeover via admin panel")
- [ ] **Are the reproduction steps complete?** (Can someone reproduce this in < 10 minutes with only your steps?)
- [ ] **Is the PoC attached?** (Request/response, screenshot, video if complex)
- [ ] **Is the impact section written from the program's perspective?** (Business risk, data at risk, affected users)
- [ ] **Is there a suggested fix?** (Even a brief one improves acceptance rate)
- [ ] **Are there any assumptions in your steps that you haven't explained?**

---

## Section 4 — Chain Opportunities
- [ ] **Can this finding be combined with another finding to increase severity?**
- [ ] **Does this finding enable another attack that's currently listed as lower severity?**
- [ ] **Is there a privilege escalation path from this finding?**

---

## Verdict Options
After completing the checklist, assign one verdict:

| Verdict | Meaning |
|---------|---------|
| `READY` | All checks pass. Report is complete and solid. |
| `NEEDS_IMPROVEMENT` | Specific weak points identified. Loop back to improve stage. |
| `NEEDS_INFO` | Blocked — need user to provide something (credentials, clarification, tool access). |
| `CHAIN` | Better submitted as part of a chain. Link to other finding IDs. |
| `DROP` | Does not survive scrutiny. Not worth submitting. |
