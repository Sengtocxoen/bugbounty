# Counter-Path Review Checklist

> Devil's advocate review. For each finding, challenge every assumption before submitting.
> Goal: find what a skeptical triager would reject, then fix it preemptively.

---

<<<<<<< HEAD
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
=======
## Section 1 — Is This Real? (Validity)
>>>>>>> e010006b73b73ffaa3bcf6a5cdd9fb13b046b64f

- [ ] **Can a WAF/filter block this in production?** Did you test prod or just staging? Cloudflare/AWS WAF may block payloads that work in Burp Repeater.
- [ ] **Is this actually exploitable, or just observable?** "The field reflects input" is not a vuln. "The field executes script in another user's session" is.
- [ ] **Does exploiting this require a precondition that's unlikely?** Specific user role, account state, race condition timing, victim using a specific browser.
- [ ] **Is this actually by design?** Could this be an intentional feature? Check docs/changelog.
- [ ] **Is the target in scope?** Re-check program.md scope. Check for CDN/third-party exclusions.
- [ ] **Is this already patched?** Re-test on fresh session. Clear cookies/cache.
- [ ] **Is your PoC reproducible by someone else?** Would a triager follow your steps exactly in under 10 minutes?

---

## Section 2 — Common False Positives (learned from real testing)

### IDOR False Positives
- [ ] **Does the server actually use the path/query parameter?** Many APIs ignore the userId in the URL and return the authenticated user's data regardless. A 200 OK for any userId does NOT prove IDOR.
- [ ] **Did you test with two accounts that have DIFFERENT data?** The only way to prove IDOR is: Account A's token + Account B's ID returns Account B's data (not Account A's data and not empty).
- [ ] **Is the empty response `[]` your data or theirs?** If both your ID and another ID return `[]`, you haven't proven anything.

### XSS/Token Theft Chain False Positives
- [ ] **Does the XSS origin match the API/token origin?** XSS on `login.example.com` cannot read tokens from `api.example.com` via iframe (different origin = blocked by browser).
- [ ] **Does `X-Frame-Options: SAMEORIGIN` help or hurt your chain?** If the token-bearing page has SAMEORIGIN, your XSS page on a different subdomain cannot iframe it.
- [ ] **Is the token in an HttpOnly cookie?** If yes, XSS cannot read it via `document.cookie`.
- [ ] **Does `Access-Control-Allow-Origin: *` actually help?** Wildcard CORS blocks `withCredentials: true`. If auth uses cookies, CORS wildcard doesn't enable cross-origin auth requests.

### CORS False Positives
- [ ] **Does the API use cookies or Bearer tokens?** `ACAO: *` with cookies = browser blocks credentials. `ACAO: *` with Bearer tokens = the attacker needs to already have the token (circular dependency unless combined with token theft).
- [ ] **Does the server reflect Origin or always return `*`?** `*` is less exploitable than reflected origin with credentials.

### Endpoint Discovery False Positives
- [ ] **Is this an SPA catch-all returning 200 for everything?** Many React/Angular apps return 200 OK with the SPA shell HTML for ANY path. Check Content-Type — if it's `text/html` for `/api/admin`, it's the SPA, not a real endpoint.
- [ ] **Is the 400/500 error from the application or the infrastructure?** Nginx/CloudFront/ELB errors are not the same as application errors. `400 Bad Request` from nginx just means the request format is wrong.

---

## Section 3 — Impact Reality Check

- [ ] **Is the impact you claimed the real worst-case, or did you overstate it?** "Any website can steal viewing history" requires the attacker to ALSO have the victim's Bearer token.
- [ ] **Is the impact you claimed realistic, or hypothetical?** Walk through the full attack step by step. Does every step actually work?
- [ ] **Does the impact require additional findings to realize?** If so, do you HAVE those additional findings, or are you assuming they exist?
- [ ] **What's the blast radius?** One user? All users? Specific role? Admin only?
- [ ] **Would the triager say "so what"?** Can you explain why this matters in one sentence?

---

## Section 4 — Report Quality

- [ ] **Is the title specific enough?** Bad: "IDOR on API". Good: "IDOR on /api/user/:id exposes PII (email, phone) of any user via sequential ID enumeration"
- [ ] **Are the reproduction steps complete?** Can someone reproduce in < 10 minutes with ONLY your steps?
- [ ] **Is every request/response captured?** Full HTTP headers + body, not just "I got a 200"
- [ ] **Is the impact written from the PROGRAM'S perspective?** What data/users/money is at risk?
- [ ] **Is there a suggested fix?** Even brief fixes improve acceptance rate.
- [ ] **Did you explain WHY this is a bug, not just WHAT you observed?** "The server returns 200" is observation. "The server lacks authorization check comparing token.sub to path.userId" is explanation.

---

## Section 5 — Chain Opportunities

- [ ] **Can this finding be combined with another to increase severity?**
- [ ] **Does this finding enable another attack?**
- [ ] **Is there a privilege escalation path?**
- [ ] **Have you TESTED each link in the chain?** Theoretical chains that break at one link are worthless. Test every step.

---

## Section 6 — Program-Specific Checks

- [ ] **Re-read the "Out of Scope" section** — is any part of your finding excluded?
- [ ] **Re-read "Known Issues"** — is this already acknowledged?
- [ ] **Check your previous reports** — are you re-reporting something already closed?
- [ ] **Check the program's response history** — do they typically accept this type of finding?

---

## Verdict Options

| Verdict | Meaning |
|---------|---------|
| `READY` | All checks pass. Report is solid. Ship it. |
| `NEEDS_IMPROVEMENT` | Specific weak points identified. List them in "Specific asks". |
| `NEEDS_INFO` | Blocked — need user to provide something (second account, creds, tool access). |
| `CHAIN` | Too weak alone. Link to other finding IDs for combined submission. |
| `DROP` | Does not survive scrutiny. Don't waste time improving. Move on. |
