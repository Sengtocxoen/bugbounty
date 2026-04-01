# Improve Loop Prompt

> Use this prompt when a finding has verdict=NEEDS_IMPROVEMENT after counter-path review.

---

## IMPROVE PROMPT (paste into Claude Code)

```
Read F:/bb-workspace/findings/[F00X-slug].md

The counter-path review identified the following weak points:
[paste the "Specific asks" and "Weak points" from the finding file]

Your job is to improve this finding and its report. For each weak point:

1. ADDRESS the issue — strengthen the PoC, clarify the impact, add missing evidence, fix the reproduction steps
2. If you cannot address an issue without more information, add it to the NEEDS_INFO list in the finding file
3. Re-score the Report Quality (Clarity, Reproducibility, Impact, Evidence) in the finding file
4. Regenerate the report using /bb-report
5. Save the improved draft to F:/bb-workspace/reports/drafts/[F00X]-draft-v[N].md
6. Increment the counter-path loop counter in the finding file
7. Re-run the counter-path checklist from F:/bb-workspace/counter-path/_counter-checklist.md
8. Update the verdict

If Report Total >= 16/20 AND counter-path verdict = READY:
- Save to F:/bb-workspace/reports/final/[F00X]-final.md
- Update STATUS.md: set finding status = FINAL

If loop count >= 3 and still not READY:
- Set verdict = NEEDS_INFO
- Write specific questions to STATUS.md "Blocked / Needs Human Input"
```

---

## WHAT GOOD IMPROVEMENT LOOKS LIKE

### Weak PoC → Strong PoC
Before: "I observed the field reflects input"
After: Full HTTP request/response showing payload execution, screenshot of alert/data access, video for complex flows

### Vague Impact → Specific Impact
Before: "An attacker could access user data"
After: "An unauthenticated attacker can enumerate all user email addresses via the /api/users endpoint by iterating integer IDs from 1 to N, confirmed on production with test accounts user_id=1001 and user_id=1002"

### Missing Reproduction → Complete Steps
Before: "Go to profile, add payload, save"
After:
1. Log in as user A (test@example.com / Password123)
2. Navigate to /profile/edit
3. In the "Bio" field, enter: `<img src=x onerror=alert(document.cookie)>`
4. Click Save
5. Log in as user B (test2@example.com / Password123)
6. Navigate to user A's public profile at /user/1001
7. Observe alert box fires with user B's session cookie

### Weak Title → Strong Title
Before: "XSS vulnerability"
After: "Stored XSS in profile bio field allows session cookie theft from any user who views the victim's profile"
