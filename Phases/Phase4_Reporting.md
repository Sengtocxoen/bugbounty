# Phase 4: Reporting

**Goal:** Document and submit findings professionally for maximum impact.

---

## Overview

Reporting is the critical final phase that determines whether your hard work results in a bounty. A well-written report demonstrates professionalism, clearly communicates impact, and helps security teams fix vulnerabilities quickly.

```
+-------------------+     +-------------------+     +-------------------+
|  Verified Vulns   | --> |  Documentation    | --> |  Submission       |
+-------------------+     +-------------------+     +-------------------+
| - PoCs            |     | - Clear steps     |     | - Platform submit |
| - Evidence        |     | - Impact analysis |     | - Track status    |
| - Severity        |     | - Screenshots     |     | - Follow up       |
+-------------------+     +-------------------+     +-------------------+
```

---

## Report Structure

### Standard Report Template

```markdown
# [Vulnerability Type] in [Feature/Endpoint]

## Summary
[1-2 sentences describing the vulnerability and its impact]

## Severity
[Critical/High/Medium/Low] - CVSS: X.X

## Affected Asset
- URL: [Full URL]
- Parameter: [Vulnerable parameter]
- Endpoint: [API endpoint if applicable]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]
...

## Proof of Concept
[Include code, curl commands, or detailed technical proof]

## Impact
[Detailed explanation of security impact]

## Remediation Recommendation
[Optional but helpful suggestion for fix]

## Supporting Material
- [Screenshot 1]
- [Video URL]
- [Additional evidence]
```

### Section Guidelines

#### Summary
- One paragraph, no more than 3-4 sentences
- State what the vulnerability is
- State what an attacker can do
- State what data/functionality is affected

**Good Example:**
> An Insecure Direct Object Reference vulnerability in the `/api/orders/{id}` endpoint allows authenticated users to access order details belonging to other users by modifying the order ID parameter. This exposes sensitive PII including shipping addresses, payment details, and purchase history of all customers.

**Bad Example:**
> I found an IDOR.

#### Steps to Reproduce
- Numbered list
- Start from zero state
- Include every click and input
- Include exact values to use
- Should work for someone unfamiliar with the app

**Good Example:**
```
1. Create a new account at https://target.com/register using email test@example.com
2. Login to the account
3. Create a new order by adding any item to cart and completing checkout
4. Note the order ID in the URL (e.g., order ID = 12345)
5. Intercept the request to /api/orders/12345 using Burp Suite
6. Modify the order ID to 12344 (another user's order)
7. Forward the request
8. Observe that the response contains order details for the other user
```

#### Proof of Concept

**Include Full Request/Response:**
```http
GET /api/orders/12344 HTTP/1.1
Host: api.target.com
Authorization: Bearer eyJhbG...
Accept: application/json
User-Agent: amazonvrpresearcher_yourh1username

---

HTTP/1.1 200 OK
Content-Type: application/json

{
  "order_id": 12344,
  "user_email": "victim@example.com",
  "shipping_address": "123 Victim Street...",
  "items": [...],
  "total": 99.99
}
```

**For Amazon GenAI Reports Include:**
- Timestamp of test
- IP address used
- Full prompt string
- Security impact

#### Impact Assessment

Connect the vulnerability to business impact:

| Vulnerability | Technical Impact | Business Impact |
|---------------|------------------|-----------------|
| IDOR on orders | Access other users' data | Privacy breach, GDPR violation |
| SSRF to metadata | AWS credentials leaked | Full infrastructure compromise |
| SQLi | Database access | Data breach, compliance failure |
| XSS stored | Session hijacking | Account takeover, fraud |

---

## Program-Specific Requirements

### Amazon VRP

**Report Must Include:**
- Proof asset is in scope (not AWS, .a2z, .dev, etc.)
- User-Agent used: `amazonvrpresearcher_yourh1username`
- Test account email used

**GenAI Reports:**
- Timestamp
- IP address
- Full prompt string
- Security impact demonstration
- DO NOT include generated sensitive/explicit content

**Subdomain Takeover:**
- Serve HTML on hidden path
- Include H1 username in HTML comment
- Provide path to proof file

### Shopify

**Report Must Include:**
- Confirmation testing was on YOUR test store
- Store URL you created
- Clear security impact

**NEVER:**
- Report testing on merchant stores
- Contact Shopify Support about reports
- Disclose before resolution

---

## Severity Rating

### CVSS 3.1 Quick Reference

| Score | Rating | Description |
|-------|--------|-------------|
| 9.0-10.0 | Critical | Full system compromise, mass data breach |
| 7.0-8.9 | High | Significant data exposure, privilege escalation |
| 4.0-6.9 | Medium | Limited data exposure, specific conditions |
| 0.1-3.9 | Low | Minimal impact, theoretical scenarios |

### Common Vulnerability Ratings

| Vulnerability Type | Typical Range | Notes |
|-------------------|---------------|-------|
| RCE | 9.0-10.0 | Critical |
| SQLi with exfiltration | 7.0-9.5 | High-Critical |
| SSRF to internal | 7.0-9.0 | Depends on access |
| IDOR with PII | 6.0-8.0 | Depends on data |
| Stored XSS | 5.0-7.0 | Depends on context |
| Reflected XSS | 4.0-6.0 | Requires user interaction |
| CSRF | 4.0-6.0 | Depends on action |
| Subdomain takeover | 5.0-7.0 | Depends on use case |

---

## Evidence Best Practices

### Screenshots

**Do:**
- High resolution and readable
- Highlight relevant areas
- Show full URL bar
- Include timestamps
- Redact unrelated PII

**Don't:**
- Blur critical details
- Use tiny screenshots
- Skip context

### Video Recording

**When to Use:**
- Complex multi-step exploits
- Race conditions
- Time-sensitive vulnerabilities
- Browser-based attacks

**Tools:**
- OBS Studio
- Loom
- Screen recording native to OS

### Request/Response Logs

**Always Include:**
- Full HTTP request
- Full HTTP response
- All relevant headers
- Any cookies/tokens (redact as needed)

---

## Writing Quality

### Be Clear and Concise

**Good:**
> The application fails to validate user ownership of the order resource, allowing any authenticated user to access any order by manipulating the order_id parameter.

**Bad:**
> I was testing your application and I noticed that when I changed the ID in the URL, I could see other people's stuff. This is a big problem because hackers could steal data.

### Be Professional

- Stick to facts
- Avoid emotional language
- Don't threaten or demand
- Be respectful of triagers

### Be Helpful

- Suggest remediations
- Note similar issues you noticed
- Provide complete information upfront

---

## Pre-Submission Checklist

```markdown
## Report Quality Checklist

### Content
- [ ] Clear, descriptive title
- [ ] Concise summary with impact
- [ ] Severity with CVSS score
- [ ] Complete steps to reproduce
- [ ] Working proof of concept
- [ ] Impact clearly explained
- [ ] All evidence attached

### Technical
- [ ] Full requests/responses included
- [ ] Screenshots are clear
- [ ] Video attached (if needed)
- [ ] Tested from clean state
- [ ] Reproducible by others

### Program Compliance
- [ ] Asset verified in scope
- [ ] Rules followed during testing
- [ ] Required information included
- [ ] No prohibited content

### Professionalism
- [ ] Grammar and spelling checked
- [ ] Clear, concise language
- [ ] No emotional/threatening tone
- [ ] Properly formatted
```

---

## After Submission

### Expected Timeline

| Stage | Typical Duration |
|-------|------------------|
| Initial Response | 1-5 days |
| Triage | 1-2 weeks |
| Validation | 1-4 weeks |
| Resolution | 2-12 weeks |
| Bounty | After fix deployed |

### Communication

**Do:**
- Be patient
- Respond promptly to questions
- Provide additional info if requested
- Thank triagers for their work

**Don't:**
- Send multiple follow-ups
- Be rude or demanding
- Publicly discuss pending reports
- Contact support about reports (Shopify)

### If Marked Duplicate

- Ask for report ID of original
- Learn from the timing
- Consider if your report adds value
- Move on professionally

### If Marked Informative

- Ask for feedback if possible
- Understand why it wasn't accepted
- Improve methodology for next time

### If Accepted

- Thank the team
- Track fix deployment
- Retest after fix
- Report bypasses if found

---

## Report Templates by Vulnerability

### IDOR Report

```markdown
# IDOR: Unauthorized Access to [Resource] via [Parameter]

## Summary
An Insecure Direct Object Reference vulnerability in [endpoint] allows authenticated users to access [resource type] belonging to other users by modifying the [parameter] parameter.

## Severity
[High/Medium] - CVSS: X.X (based on data sensitivity)

## Affected Asset
- URL: [URL]
- Parameter: [parameter name]

## Steps to Reproduce
1. Login as User A
2. Create/access [resource]
3. Note the [resource ID]
4. Modify [resource ID] to another user's resource
5. Observe unauthorized access

## Impact
- Access to [specific data types]
- Affects [number/scope] of users
- [Compliance implications if applicable]

## Evidence
[Screenshots/Requests]
```

### SSRF Report

```markdown
# SSRF: Server-Side Request Forgery in [Feature]

## Summary
A Server-Side Request Forgery vulnerability in [feature] allows attackers to make the server send HTTP requests to arbitrary internal and external addresses.

## Severity
[Critical/High] - CVSS: X.X

## Affected Asset
- URL: [URL]
- Parameter: [parameter accepting URL]

## Steps to Reproduce
1. Navigate to [feature]
2. Input URL: [internal address]
3. Submit request
4. Observe server-side request

## Proof of Concept
[Request/Response showing internal access]

## Impact
- Access to internal services
- [Cloud metadata access if applicable]
- Potential for further exploitation

## Evidence
[Screenshots/Requests/Collaborator logs]
```

---

## Filing System

### Organize Reports

```
Program/
└── Phase4_Reports/
    ├── submitted/
    │   ├── 2025-01-15_IDOR_orders_api.md
    │   ├── 2025-01-16_SSRF_webhook.md
    │   └── 2025-01-17_XSS_search.md
    ├── drafts/
    │   └── pending_sqli_login.md
    └── tracking.md
```

### Tracking Template

```markdown
# Report Tracking

| Date | ID | Title | Severity | Status | Bounty |
|------|-----|-------|----------|--------|--------|
| 2025-01-15 | #123456 | IDOR in orders | High | Triaged | - |
| 2025-01-16 | #123457 | SSRF in webhook | Critical | Resolved | $5000 |
| 2025-01-17 | #123458 | XSS in search | Medium | Duplicate | - |
```

---

## Continuous Improvement

### After Each Report

- [ ] What worked well?
- [ ] What could be improved?
- [ ] How long did each phase take?
- [ ] Were there any scope issues?
- [ ] What would you do differently?

### Track Statistics

- Reports submitted
- Acceptance rate
- Average severity
- Common rejection reasons
- Total bounties earned

---

## Return to Earlier Phases

After reporting, the cycle continues:

- **Fix Deployed** -> Retest (Phase 3)
- **New Features** -> New Recon (Phase 1)
- **Bypass Found** -> New Report (Phase 4)
- **Similar Vuln Suspected** -> Analysis (Phase 2)

---

## Resources

- [HackerOne Report Writing Best Practices](https://docs.hackerone.com/hackers/submitting-reports.html)
- [Bug Bounty Report Templates](https://github.com/ZephrFish/BugBountyTemplates)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
