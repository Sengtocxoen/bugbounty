# Improve Loop Prompt

> Use when a finding has verdict=NEEDS_IMPROVEMENT after counter-path review.

---

## IMPROVE PROMPT (paste into Claude Code)

```
Read /home/kali/Desktop/bugbounty/bb-workspace/findings/[F00X-slug].md

The counter-path review identified these weak points:
[paste "Specific asks" and "Weak points" from the finding file]

For each weak point:
1. ADDRESS the issue — strengthen PoC, clarify impact, add evidence, fix steps
2. If you can't address without more info, add to NEEDS_INFO in finding file
3. Re-score Report Quality in the finding file
4. Save improved draft to /home/kali/Desktop/bugbounty/bb-workspace/reports/drafts/[F00X]-draft-v[N].md
5. Increment counter-path loop counter
6. Re-run counter-path checklist
7. Update verdict

If Report Total >= 16/20 AND verdict = READY:
→ Save to /home/kali/Desktop/bugbounty/bb-workspace/reports/final/[F00X]-final.md
→ Update STATUS.md: finding status = FINAL

If loop count >= 3 and still not READY:
→ Set verdict = NEEDS_INFO
→ Write specific questions to STATUS.md
```

---

## COMMON IMPROVEMENT PATTERNS

### "Can't prove IDOR — only one test account"
**Fix:** Ask user for second account. Or: prove the server validates ownership on OTHER endpoints (showing inconsistency). Or: show the parameter IS used via different responses for valid vs invalid IDs (404 vs 200 proves the ID is looked up, not ignored).

### "Chain breaks at cross-origin step"
**Fix:** Remove the cross-origin claim. Reframe as: the vulnerability is X (proven), and IF combined with a separate XSS (not yet found), it escalates to Y. Submit X alone at its standalone severity.

### "WAF blocks the payload"
**Fix:** Try WAF bypass techniques. Or: test on staging/UAT if in scope. Or: demonstrate the vulnerability exists by showing the application processes the input (error message changes, behavior changes) even if the full payload is blocked. Note that prod has WAF but the underlying code is vulnerable.

### "Theoretical impact only"
**Fix:** Either find a way to demonstrate real impact, or downgrade severity and submit as-is. A well-written Medium beats a poorly-proven Critical.

### "Same response for all inputs"
**Fix:** This is likely a false positive. Test with:
- Valid ID → response
- Invalid ID → response
- Your own ID → response
- No parameter → response
If all four are identical, the parameter is ignored. DROP the finding.

### "Triager will say 'so what'"
**Fix:** Connect the technical finding to business impact:
- "Attacker can read user email" → "Attacker can enumerate all 50,000 users and sell the list"
- "XSS on login page" → "Attacker can steal credentials of any user who clicks the link"
- "SSRF to internal network" → "Attacker can reach the metadata service and steal AWS credentials"
