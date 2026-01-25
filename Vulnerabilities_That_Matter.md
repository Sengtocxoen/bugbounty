# Vulnerabilities That Matter for Bug Bounty

> Based on: [Wiz Bug Bounty Masterclass - Foundations](https://www.wiz.io/bug-bounty-masterclass/foundations/the-vulnerabilities-that-matter)

This document outlines the key vulnerability categories that consistently yield high-impact findings in bug bounty programs.

---

## Core Hunter Competencies

Before diving into vulnerability types, successful bug bounty hunting requires:

1. **Curiosity** - Experimental mindset to probe and question application behavior
2. **Pattern Recognition** - Identifying exploitable indicators from subtle clues
3. **Persistence** - Iterative testing approaches when initial attempts fail

---

## The 6 Vulnerability Categories That Matter

### 1. Insecure Direct Object Reference (IDOR)

**What It Is:**
Access data that doesn't belong to you by changing an ID number in the URL or API request.

**Root Cause:**
Applications validate that requests are authenticated but fail to verify user ownership of the requested resource.

**Testing Approach:**
```
1. Identify endpoints with resource IDs (user_id, order_id, file_id, etc.)
2. Create two test accounts
3. Capture a request from Account A referencing a resource
4. Modify the ID to reference Account B's resource
5. Check if access is granted without proper authorization
```

**Common Locations:**
- `/api/users/{user_id}/profile`
- `/api/orders/{order_id}`
- `/api/documents/{document_id}/download`
- `/api/accounts/{account_id}/settings`

**Impact Levels:**
| Data Type | Severity |
|-----------|----------|
| Personal/Financial data | Critical |
| Private documents | High |
| User preferences | Medium |
| Public data | Low |

---

### 2. Server-Side Request Forgery (SSRF)

**What It Is:**
Trick an application's server into making a web request on your behalf to internal or external resources.

**Root Cause:**
Applications accept URLs as input without validating destinations, allowing attackers to access internal infrastructure.

**Testing Approach:**
```
1. Find features that accept URLs (webhooks, imports, image fetchers)
2. Try internal addresses: http://127.0.0.1, http://localhost
3. Try cloud metadata endpoints: http://169.254.169.254/
4. Try internal network ranges: http://10.0.0.1, http://192.168.1.1
5. Use DNS rebinding or bypass techniques for filters
```

**High-Value Targets:**
- AWS Metadata: `http://169.254.169.254/latest/meta-data/`
- GCP Metadata: `http://metadata.google.internal/computeMetadata/v1/`
- Azure Metadata: `http://169.254.169.254/metadata/instance`

**Common Vulnerable Features:**
- Webhook URLs
- PDF generators
- Image/URL fetchers
- Import from URL
- Preview generators

---

### 3. Subdomain Takeovers

**What It Is:**
Claiming control of a subdomain by taking over abandoned third-party service configurations.

**Root Cause:**
DNS records (CNAME) point to unclaimed resources on third-party services. When the service account is deleted but DNS remains, attackers can claim the service.

**Testing Approach:**
```
1. Enumerate all subdomains of target
2. Check for CNAME records pointing to third-party services
3. Look for error messages indicating unclaimed resources:
   - "There isn't a GitHub Pages site here"
   - "NoSuchBucket" (AWS S3)
   - "Domain not configured" (Shopify)
4. Claim the resource on the service
5. Serve content on the subdomain
```

**Vulnerable Services to Check:**
| Service | Fingerprint |
|---------|-------------|
| GitHub Pages | "There isn't a GitHub Pages site here" |
| AWS S3 | "NoSuchBucket" |
| Heroku | "No such app" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Azure | "NXDOMAIN" with azure-related CNAME |

---

### 4. Exposed Files and Leaked Secrets

**What It Is:**
Accidental exposure of sensitive files, directories, and credentials in public repositories or web servers.

**Root Cause:**
- Development artifacts left in production
- Misconfigured web servers exposing directories
- Secrets committed to public Git repositories

**Testing Approach:**

**File/Directory Exposure:**
```
1. Check for common sensitive paths:
   - /.env
   - /.git/config
   - /backup/
   - /config.php.bak
   - /web.config
   - /.aws/credentials

2. Use tools: dirsearch, ffuf, gobuster
3. Check robots.txt for hidden paths
4. Review source code for path references
```

**GitHub Secret Scanning:**
```
1. Search organization repos for:
   - API keys
   - AWS credentials
   - Database passwords
   - Private keys

2. GitHub dorks:
   - "org:company password"
   - "org:company api_key"
   - "org:company AWS_SECRET"
```

**High-Value Files:**
- `.env` - Environment variables with secrets
- `.git/` - Version control exposing history
- `config.php`, `settings.py` - Application configs
- `backup.sql`, `dump.sql` - Database dumps
- `id_rsa`, `*.pem` - Private keys

---

### 5. Business Logic Flaws

**What It Is:**
Flaws in the application's intended workflow rather than code mistakes. The application functions as designed but contains exploitable loopholes.

**Root Cause:**
Developers implement features without considering all edge cases or abuse scenarios.

**Testing Approach:**
```
1. Understand the intended workflow completely
2. Map out all state transitions
3. Try to:
   - Skip steps in multi-step processes
   - Perform actions out of order
   - Use negative values, zero values, edge cases
   - Apply discounts/credits multiple times
   - Modify quantities after price calculation
```

**Example Scenarios:**

**E-commerce:**
- Add item to cart -> Apply discount -> Reduce quantity -> Discount persists
- Purchase with negative quantity
- Race conditions on limited stock
- Coupon code stacking

**Authentication:**
- Skip 2FA step in login flow
- Password reset token reuse
- Account recovery logic flaws

**Financial:**
- Rounding errors in currency conversion
- Race conditions on balance transfers
- Refund processing logic

---

### 6. 0-Day and Novel Misconfigurations

**What It Is:**
Time-sensitive vulnerabilities following public disclosure. Hunters race to identify affected systems before malicious exploitation.

**Root Cause:**
Organizations fail to patch quickly after CVE disclosure, leaving windows of opportunity.

**Testing Approach:**
```
1. Monitor security advisories and CVE databases
2. When new vulnerability is disclosed:
   - Identify affected software/versions
   - Search for targets using that software
   - Develop detection methodology
   - Test responsibly
3. Report before widespread exploitation
```

**Resources to Monitor:**
- CVE databases (NVD, MITRE)
- Security mailing lists
- Vendor security bulletins
- Twitter security community
- GitHub security advisories

**Speed Matters:**
- First hours/days after disclosure are critical
- Automated scanning can identify vulnerable instances
- Responsible disclosure prevents criminal exploitation

---

## Vulnerability Priority Matrix

| Vulnerability | Impact | Difficulty | Bounty Potential |
|--------------|--------|------------|------------------|
| SSRF to Internal | Critical | Medium | $$$$$ |
| IDOR on Sensitive Data | High-Critical | Low | $$$$ |
| Business Logic (Payment) | High | Medium | $$$$ |
| Subdomain Takeover | Medium-High | Low | $$$ |
| Exposed Secrets | Variable | Low | $$ - $$$$ |
| 0-Day Exploitation | Critical | High | $$$$$ |

---

## Integration with Bug Bounty Phases

### Phase 1: Reconnaissance
- Subdomain enumeration (for takeovers)
- File/directory discovery
- Service fingerprinting

### Phase 2: Analysis
- Map application workflows (business logic)
- Identify URL input features (SSRF)
- Find ID parameters (IDOR)

### Phase 3: Exploitation
- Test IDOR on identified endpoints
- Probe SSRF vectors
- Claim abandoned subdomains
- Test business logic edge cases

### Phase 4: Reporting
- Document clear reproduction steps
- Demonstrate security impact
- Calculate severity score

---

## Quick Reference Checklist

### Before Testing Any Target:
- [ ] Identify endpoints with user-supplied IDs (IDOR)
- [ ] Find features accepting URLs (SSRF)
- [ ] Enumerate subdomains for takeover
- [ ] Check for exposed files/directories
- [ ] Map application workflows (business logic)
- [ ] Check for known CVEs in stack

### Red Flags to Investigate:
- URL parameters with sequential IDs
- Features that fetch remote content
- CNAME records to third-party services
- Directory listing enabled
- Multi-step processes with client-side state
- Recently disclosed vulnerabilities in tech stack

---

## Further Reading

- [Wiz Bug Bounty Masterclass](https://www.wiz.io/bug-bounty-masterclass/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
