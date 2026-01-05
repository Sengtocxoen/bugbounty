# Quick Reference Checklist - Bug Bounty Testing

## 🚨 CRITICAL RULES - NEVER VIOLATE

### Amazon VRP
- [ ] User-Agent: `amazonvrpresearcher_yourh1username` (MANDATORY)
- [ ] Rate limit: MAX 5 requests/second
- [ ] Email: `yourh1username@wearehackerone.com`
- [ ] NO 3rd party XSS Hunter - must be self-hosted
- [ ] NO AWS subdomains, `.a2z`, `.dev`, test/staging
- [ ] NO post-exploitation or accessing other users' accounts

### Shopify
- [ ] Email: `yourh1username@wearehackerone.com`
- [ ] Test ONLY stores you created
- [ ] NO live merchant stores
- [ ] NO contacting Shopify Support
- [ ] Register via: https://partners.shopify.com/signup/bugbounty

---

## 🎯 HIGH-VALUE VULNERABILITIES

### Critical (Highest Bounty)
- [ ] Remote Code Execution (RCE)
- [ ] SQL Injection
- [ ] XXE (XML External Entity)
- [ ] High-impact XSS (stored, account takeover)
- [ ] SSRF (Server-Side Request Forgery)

### High (Good Bounty)
- [ ] Authentication/Authorization Bypass
- [ ] Privilege Escalation
- [ ] IDOR (Insecure Direct Object Reference)
- [ ] Directory Traversal / LFI
- [ ] GenAI Prompt Injection (Amazon) - leading to data exfiltration

### Medium (Decent Bounty)
- [ ] CORS Misconfiguration
- [ ] CSRF (with impact)
- [ ] Open Redirect (with impact)
- [ ] Request Smuggling
- [ ] Information Disclosure (sensitive data)

---

## 📋 TESTING CHECKLIST

### Authentication & Authorization
- [ ] Account enumeration (username/email)
- [ ] Weak password policy
- [ ] 2FA bypass
- [ ] Password reset token issues
- [ ] Session fixation
- [ ] JWT/Token manipulation
- [ ] Horizontal privilege escalation (access other users)
- [ ] Vertical privilege escalation (admin access)
- [ ] IDOR in all endpoints
- [ ] OAuth implementation flaws

### Injection Vulnerabilities
- [ ] SQL Injection (all input fields)
- [ ] Command Injection
- [ ] XXE (file upload, XML endpoints)
- [ ] XSS (stored, reflected, DOM)
- [ ] Template Injection (SSTI)
- [ ] LDAP Injection
- [ ] NoSQL Injection
- [ ] GraphQL Injection

### Business Logic
- [ ] Payment bypass
- [ ] Cart manipulation (negative prices)
- [ ] Order modification
- [ ] Discount code abuse
- [ ] Inventory manipulation
- [ ] Race conditions
- [ ] Multi-step process bypass

### API Testing
- [ ] Missing authentication
- [ ] Weak authorization
- [ ] Rate limiting bypass
- [ ] Mass assignment
- [ ] GraphQL depth/complexity bypass
- [ ] GraphQL field-level auth bypass
- [ ] API key leakage
- [ ] Batch query attacks

### SSRF Testing
- [ ] Webhook URLs
- [ ] Image processing
- [ ] PDF generation
- [ ] Import/export features
- [ ] URL validation functions
- [ ] GenAI features fetching URLs

### Amazon-Specific
- [ ] GenAI prompt injection
- [ ] GenAI output handling (XSS, SSRF)
- [ ] Cross-customer data access via AI
- [ ] Mobile app API testing
- [ ] Subdomain takeover (wildcard domains)

### Shopify-Specific
- [ ] Multi-tenant isolation bypass
- [ ] Cross-store data access
- [ ] Partner portal privilege escalation
- [ ] Webhook manipulation
- [ ] App installation vulnerabilities

---

## 🔧 TOOLS SETUP

### Burp Suite Configuration
- [ ] User-Agent match/replace rule (Amazon)
- [ ] Rate limiting extension
- [ ] Custom wordlists loaded
- [ ] Extensions installed (J2EE Scanner, etc.)

### Reconnaissance
- [ ] Subdomain enumeration tools ready
- [ ] Technology detection tools
- [ ] Wayback Machine tools
- [ ] API discovery tools

### Testing Infrastructure
- [ ] Self-hosted XSS Hunter (Amazon requirement)
- [ ] VPS/server for blind testing
- [ ] Test accounts created
- [ ] Mobile app analysis tools (Amazon)

---

## 📝 REPORT PREPARATION

### Before Submitting
- [ ] Asset is in-scope (proof included)
- [ ] Functional PoC works
- [ ] Clear reproduction steps
- [ ] Screenshots/video evidence
- [ ] Security impact demonstrated
- [ ] CVSS score calculated
- [ ] No rule violations
- [ ] All requirements met (User-Agent, email, etc.)

### Report Quality
- [ ] Clear title
- [ ] Detailed summary
- [ ] Numbered reproduction steps
- [ ] Impact assessment
- [ ] Remediation suggestions (optional)

### Amazon GenAI Reports
- [ ] Timestamp included
- [ ] IP address included
- [ ] Prompt string included
- [ ] Security impact explained
- [ ] NO sensitive/explicit content

---

## 🎓 DAILY ROUTINE

### Morning (15 min)
- [ ] Check program updates
- [ ] Review scope changes
- [ ] Check HackerOne for new accepted reports
- [ ] Plan today's focus area

### Testing Session
- [ ] Verify all requirements met
- [ ] Test one vulnerability type at a time
- [ ] Document findings immediately
- [ ] Take screenshots/videos
- [ ] Follow rate limits

### End of Day (30 min)
- [ ] Review all findings
- [ ] Prioritize for reporting
- [ ] Research similar vulnerabilities
- [ ] Update notes

---

## 🚫 OUT-OF-SCOPE (Don't Waste Time)

### Amazon
- ❌ Clickjacking
- ❌ Self-XSS
- ❌ Email spoofing (SPF)
- ❌ Missing security headers
- ❌ Missing cookie flags
- ❌ Minimal-impact CSRF (login/logout)
- ❌ Stack traces/path disclosure
- ❌ SSL/TLS issues (with mitigations)
- ❌ DOS/DDOS
- ❌ Scanner outputs
- ❌ Model hallucinations (GenAI)

### Shopify
- ❌ Testing live merchants
- ❌ Issues without security impact
- ❌ Out-of-scope assets

---

## 💡 PRO TIPS

1. **Read Accepted Reports:** Study what gets rewarded
2. **Focus on Impact:** Demonstrate real security risk
3. **Manual Testing > Automation:** Creative thinking finds bugs
4. **Understand the App:** Deep knowledge = better findings
5. **Stay Updated:** Programs evolve constantly
6. **Quality > Quantity:** One great report > ten weak ones
7. **Be Patient:** Bug bounty is a long game

---

## 📊 PRIORITY MATRIX

### High Priority + High Impact
- RCE, SQLi, XXE
- Auth bypass with admin access
- SSRF to internal networks
- GenAI data exfiltration

### High Priority + Medium Impact
- Stored XSS in user-facing features
- IDOR accessing sensitive data
- Business logic flaws (payment bypass)

### Medium Priority + High Impact
- Reflected XSS
- CSRF with impact
- Information disclosure (PII)

### Low Priority (Still Worth Reporting)
- Open redirects
- CORS misconfigurations
- Low-impact information disclosure

---

## 🔍 TESTING WORKFLOW

1. **Recon** → Find targets
2. **Map** → Understand architecture
3. **Test** → Focus on one area
4. **Document** → Record everything
5. **Verify** → Confirm vulnerability
6. **PoC** → Create working exploit
7. **Report** → Submit with evidence
8. **Learn** → Study feedback

---

**Remember:** Follow all rules, test responsibly, and focus on demonstrating real security impact. Good luck! 🐛💰

