# Finding: [TITLE]
> Copy this file, rename to F00X-slug.md, fill every section.

## Metadata
- **ID:** F00X
- **Title:**
- **Severity:** Critical / High / Medium / Low / Info
- **CWE:**
- **CVSS Score:** (optional)
- **Found:** <!-- date -->
- **Stage found:** Recon / Hunt-Web / Hunt-API / Chain / Manual

## Target
- **URL/Endpoint:**
- **Method:** GET / POST / PUT / PATCH / DELETE
- **Parameter/Field:**
- **Auth required:** Yes / No / Partial
- **Works on:** Prod / Staging / UAT / Both

## Taint Map (REQUIRED — fill before triage)
- **Source**: <!-- Where does attacker-controlled data enter? (HTTP param, file upload, JWT claim, webhook URL...) -->
- **Propagator**: <!-- How does the data flow? (function calls, ORM filters, serialization steps...) -->
- **Sanitizer**: <!-- What validation exists? Can it be bypassed? Does it fail open? -->
- **Sink**: <!-- Where does it land? (SQL query, eval(), URL fetcher, file write, template renderer...) -->

**State Transition Plan:**
```
To achieve [Final Effect]:
  → Need [Precondition N]
    → Need [Precondition N-1]
      → Need [Entry point / this vulnerability]
```

---

## Description
<!-- Clear 2-3 sentence explanation of the vulnerability -->

## Steps to Reproduce
```
1. 
2. 
3. 
```

## Proof of Concept
```
# Request:


# Response:


# Screenshot/evidence path:
```

## Impact
<!-- What can an attacker do? What data/function is affected? What's the business impact? -->

## Root Cause
<!-- Why does this vulnerability exist? What assumption/control is missing? -->

## Affected Components
```
# List files, services, endpoints affected
```

## Suggested Fix
<!-- Brief remediation advice -->

---
## Reality Check (fill BEFORE triage — be honest)

### Data Ownership Proof
<!-- CRITICAL for IDOR: Did you verify the returned data belongs to the OTHER user?
     Not just "200 OK for any ID" — that could mean the server ignores the parameter.
     You need: Account A data ≠ Account B data when queried cross-account. -->
- [ ] Confirmed data in response belongs to the queried user (not the authenticated user)
- [ ] Tested with two accounts that have DIFFERENT data
- [ ] N/A — not an IDOR finding

### Cross-Origin Proof (for CORS/XSS chains)
<!-- CRITICAL: Did you verify the cross-origin read actually works end-to-end?
     "Access-Control-Allow-Origin: *" doesn't help if auth uses cookies with SameSite,
     or if the token is in HttpOnly cookie, or if origins are on different domains. -->
- [ ] Verified the target uses Bearer tokens (not cookies) for the cross-origin request
- [ ] Verified withCredentials works OR tokens are obtainable cross-origin
- [ ] Verified the response contains sensitive data readable by the attacker origin
- [ ] N/A — not a cross-origin finding

### Chain Link Proof
<!-- If this finding depends on another finding to show impact: -->
- [ ] Each link in the chain is independently tested and working
- [ ] No link assumes something without proof (e.g., "the XSS could steal tokens")
- [ ] Cross-origin restrictions don't break the chain
- [ ] The chain doesn't cross scope boundaries

### False Positive Check
- [ ] Tested with invalid/garbage input — does the endpoint return the SAME response?
- [ ] Tested unauthenticated — does it still "work"? (might be catch-all route)
- [ ] Response is actual API JSON, not an SPA HTML catch-all returning 200 for everything
- [ ] Error is from the application (not the WAF/CDN/load balancer)

---
## Triage Scores (filled by triage stage)
- **Exploitability:** — / 5
- **Impact:** — / 5
- **Confidence:** — / 5
- **Uniqueness:** — / 5
- **False Positive Risk:** — / 5 <!-- 5=definitely real, 1=probably false positive -->
- **Triage Total:** — / 25
- **Triage Decision:** SUBMIT / IMPROVE / CHAIN / DROP
- **Triage Notes:**

---
## Counter-Path Review (filled by counter-path stage)
- **Counter-path loop:** 0
- **Invalidation risks:**
  - [ ] WAF/filter in place that blocks this?
  - [ ] Requires unusual precondition?
  - [ ] Impact is theoretical only?
  - [ ] Already patched/known?
  - [ ] Out of scope?
  - [ ] Server ignores the vulnerable parameter? (200 OK ≠ vulnerable)
  - [ ] Same response for valid and garbage input?
  - [ ] SPA catch-all masking as real endpoint?
- **Missing evidence:**
- **Weak points in the report:**
- **Reviewer verdict:** READY / NEEDS_IMPROVEMENT / NEEDS_INFO / DROP
- **Specific asks:**

---
## Report Quality Score (filled by improve stage)
- **Clarity:** — / 5
- **Reproducibility:** — / 5
- **Impact articulation:** — / 5
- **Evidence quality:** — / 5
- **Report Total:** — / 20
- **Submit threshold:** 16/20 minimum
- **Status:** DRAFT / IMPROVED / FINAL
