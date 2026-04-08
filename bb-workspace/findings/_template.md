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
## Triage Scores (filled by triage stage)
- **Exploitability:** — / 5 <!-- How easy to exploit? 1=needs chained setup, 5=one click -->
- **Impact:** — / 5 <!-- How severe is the outcome? -->
- **Confidence:** — / 5 <!-- How sure are we this is real? 1=theoretical, 5=confirmed RCE -->
- **Uniqueness:** — / 5 <!-- How likely is this already found/known? 1=very common, 5=novel -->
- **Triage Total:** — / 20
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
