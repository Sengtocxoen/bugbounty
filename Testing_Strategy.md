# Bug Bounty Testing Strategy: Amazon VRP & Shopify

## Executive Summary

This document provides a comprehensive analysis of both bug bounty programs and outlines a strategic approach for finding vulnerabilities. Both programs have distinct scopes, rules, and testing requirements that must be followed.

---

## 1. TARGET ANALYSIS

### Amazon VRP - Target Landscape

**In-Scope Assets:**
- **Wildcard Scope:** `*.amazon` (all retail marketplaces)
- **Geographic Coverage:** 20+ country-specific domains (amazon.com, amazon.co.uk, amazon.in, etc.)
- **Mobile Apps:**
  - Android: `com.amazon.mShop.android.shopping`
  - iOS: `amazon-shopping-297606951`

**Key Characteristics:**
- Massive attack surface with multiple subdomains per domain
- E-commerce platform with complex authentication/authorization flows
- Payment processing systems
- User account management
- Product listing and review systems
- GenAI/LLM features (new attack surface)

**Critical Out-of-Scope:**
- Anything with `aws` in subdomain
- `.a2z` domains
- `*.dev` domains
- Test/QA/staging environments
- AWS infrastructure

### Shopify - Target Landscape

**In-Scope Assets:**
- Shopify platform and infrastructure
- Partner portal
- Admin interfaces
- API endpoints
- Store management systems

**Key Characteristics:**
- Multi-tenant SaaS platform
- Merchant store isolation is critical
- API-heavy architecture
- Partner/developer ecosystem
- Payment processing
- App marketplace

**Critical Restrictions:**
- **MUST test only against stores YOU created**
- Testing live merchant stores = disqualification
- Must use `@wearehackerone.com` email for accounts

---

## 2. VULNERABILITY PRIORITIES

### Amazon VRP - High-Value Targets

#### Critical Severity (Highest Bounty Potential)
1. **Remote Code Execution (RCE)**
   - Server-side code injection
   - Command injection in admin functions
   - File upload vulnerabilities leading to RCE
   - Template injection (SSTI)

2. **SQL Injection**
   - Authentication bypass
   - Data extraction
   - Database manipulation

3. **XXE (XML External Entity)**
   - File reading
   - SSRF via XXE
   - Internal network scanning

4. **High-Impact XSS**
   - Stored XSS in user-facing features
   - XSS leading to account takeover
   - XSS in admin panels

5. **Server-Side Request Forgery (SSRF)**
   - Internal network access
   - Cloud metadata access (AWS)
   - Port scanning internal services

#### Medium-High Severity
6. **Authentication/Authorization Bypass**
   - Broken access control
   - Privilege escalation
   - IDOR (Insecure Direct Object Reference)
   - JWT/Token manipulation

7. **Directory Traversal / LFI**
   - Local file inclusion
   - Path traversal
   - Sensitive file disclosure

8. **GenAI/LLM Vulnerabilities** (NEW - High Potential)
   - Prompt injection leading to data exfiltration
   - Cross-customer data access via AI
   - Model theft
   - Unauthorized PII disclosure
   - Insecure output handling (XSS, SSRF via AI responses)

#### Testing Focus Areas for Amazon:
- **Authentication flows:** Login, registration, password reset, 2FA
- **User account management:** Profile updates, payment methods, addresses
- **Product/order systems:** Cart manipulation, order processing, reviews
- **Admin/partner portals:** If accessible, high-value targets
- **API endpoints:** GraphQL, REST APIs, mobile app APIs
- **GenAI features:** Chatbots, product recommendations, search

### Shopify - High-Value Targets

#### Critical Focus Areas
1. **Multi-Tenant Isolation Bypass**
   - Accessing other merchants' data
   - Cross-store data leakage
   - Partner account privilege escalation

2. **API Vulnerabilities**
   - GraphQL injection
   - REST API authorization bypass
   - Rate limiting bypass
   - API key leakage

3. **Authentication/Authorization Issues**
   - Admin panel access bypass
   - Partner portal privilege escalation
   - OAuth implementation flaws
   - Session management issues

4. **Payment Processing Vulnerabilities**
   - Payment bypass
   - Refund manipulation
   - Transaction tampering

5. **Store Management Functions**
   - Theme/Code injection (if accessible)
   - App installation vulnerabilities
   - Webhook manipulation

#### Testing Focus Areas for Shopify:
- **Your own test stores:** Create multiple stores to test isolation
- **Partner portal:** Developer/partner account features
- **Admin APIs:** Store management endpoints
- **GraphQL endpoints:** Often overlooked attack surface
- **Webhooks:** Callback manipulation
- **App ecosystem:** Third-party app integrations

---

## 3. TESTING METHODOLOGY

### Phase 1: Reconnaissance & Asset Discovery

#### For Amazon VRP:
```bash
# Subdomain enumeration
- Use tools: Amass, Subfinder, Sublist3r, Assetfinder
- Focus on *.amazon domains
- Filter out: aws.*, *.a2z, *.dev, test/qa/staging

# Technology stack identification
- Wappalyzer, BuiltWith
- Identify frameworks, APIs, CDNs
- Map out application architecture

# Endpoint discovery
- Directory brute-forcing (with rate limits!)
- API endpoint discovery
- Mobile app API reverse engineering
```

#### For Shopify:
```bash
# Focus on documented in-scope assets
- Review Shopify's scope page regularly
- Identify API endpoints
- GraphQL schema introspection
- Partner portal endpoints
```

### Phase 2: Vulnerability Discovery

#### Authentication & Authorization Testing

**Amazon:**
- [ ] Test login/registration flows for:
  - Account enumeration
  - Weak password policies
  - 2FA bypass
  - Session fixation
  - Password reset token issues
- [ ] Test authorization:
  - Horizontal privilege escalation (access other users' data)
  - Vertical privilege escalation (admin access)
  - IDOR in order/product/user endpoints
  - JWT token manipulation

**Shopify:**
- [ ] Test store isolation:
  - Can you access other merchants' data?
  - Cross-store IDOR
  - Partner account privilege escalation
- [ ] Admin panel access:
  - Bypass admin authentication
  - Session management flaws
  - OAuth implementation issues

#### Injection Testing

**SQL Injection:**
- [ ] Test all input fields, URL parameters, POST data
- [ ] Focus on: search, filters, user input, admin functions
- [ ] Use time-based, boolean-based, error-based techniques
- [ ] Test GraphQL endpoints for SQLi

**Command Injection:**
- [ ] File upload functions
- [ ] Admin/system functions
- [ ] API endpoints that process user input
- [ ] GenAI features that execute commands

**XXE:**
- [ ] File upload (XML files)
- [ ] API endpoints accepting XML
- [ ] Document processing features

**XSS:**
- [ ] Stored XSS: Reviews, comments, product descriptions, user profiles
- [ ] Reflected XSS: Search, error messages, URL parameters
- [ ] DOM XSS: Client-side JavaScript
- [ ] Test in admin panels (higher impact)

**SSRF:**
- [ ] Webhook/URL validation functions
- [ ] Image processing/thumbnail generation
- [ ] PDF generation
- [ ] Import/export features
- [ ] GenAI features that fetch external resources

#### Business Logic Flaws

**Amazon:**
- [ ] Cart manipulation (negative prices, quantity overflow)
- [ ] Order processing (bypass payment, modify orders)
- [ ] Review system (manipulate ratings, post fake reviews)
- [ ] Gift card/credit manipulation
- [ ] Prime membership bypass

**Shopify:**
- [ ] Payment bypass
- [ ] Discount code manipulation
- [ ] Order modification after payment
- [ ] Inventory manipulation
- [ ] Refund abuse

#### API Testing

**GraphQL:**
- [ ] Introspection queries
- [ ] Query depth/complexity bypass
- [ ] Field-level authorization bypass
- [ ] Batch query attacks

**REST APIs:**
- [ ] Missing authentication
- [ ] Weak authorization
- [ ] Rate limiting bypass
- [ ] Mass assignment
- [ ] API key leakage

#### GenAI/LLM Testing (Amazon)

**Prompt Injection:**
- [ ] System prompt extraction
- [ ] Instruction following attacks
- [ ] Data exfiltration via prompts
- [ ] Cross-customer data access

**Insecure Output Handling:**
- [ ] XSS via AI responses
- [ ] SSRF via AI-generated URLs
- [ ] Command injection via AI output

**Data Privacy:**
- [ ] PII leakage in responses
- [ ] Training data extraction
- [ ] Model theft

### Phase 3: Proof of Concept Development

**Requirements:**
- Clear reproduction steps
- Screenshots/video evidence
- Impact demonstration
- CVSS score calculation
- Functional PoC (not just theory)

---

## 4. TOOLS & TECHNIQUES

### Reconnaissance Tools
- **Subdomain enumeration:** Amass, Subfinder, Assetfinder, Sublist3r
- **Port scanning:** Nmap (with rate limits for Amazon)
- **Technology detection:** Wappalyzer, BuiltWith, WhatWeb
- **Wayback Machine:** Waybackurls, Gau (for historical endpoints)

### Vulnerability Discovery
- **Proxy tools:** Burp Suite Professional, OWASP ZAP
- **API testing:** Postman, GraphQL Playground, Insomnia
- **Fuzzing:** ffuf, wfuzz, Burp Intruder
- **SQL injection:** SQLMap (careful with rate limits)
- **XSS testing:** Custom payloads, XSS Hunter (self-hosted only for Amazon)

### Mobile App Testing (Amazon)
- **APK analysis:** JADX, APKTool
- **iOS analysis:** class-dump, Hopper
- **API interception:** Burp, mitmproxy
- **Certificate pinning bypass:** Frida, Objection

### GenAI Testing (Amazon)
- **Prompt engineering:** Custom injection payloads
- **Output analysis:** Test for XSS, SSRF, command injection in responses

### Automation (with caution)
- **Rate limiting:** Max 5 req/sec for Amazon
- **User-Agent:** Must include `amazonvrpresearcher_yourh1username`
- **Self-hosted infrastructure:** Required for blind testing (Amazon)

---

## 5. STEP-BY-STEP ACTION PLAN

### Week 1-2: Setup & Initial Recon

**Amazon VRP:**
1. ✅ Set up Burp Suite with User-Agent rule
2. ✅ Create Amazon account with `yourh1username@wearehackerone.com`
3. ✅ Enumerate subdomains for major Amazon domains
4. ✅ Map out application architecture
5. ✅ Identify high-value endpoints (auth, payment, admin)
6. ✅ Set up self-hosted XSS Hunter (if needed)

**Shopify:**
1. ✅ Create Shopify account with `@wearehackerone.com` email
2. ✅ Register via bug bounty signup link
3. ✅ Create 2-3 test stores
4. ✅ Explore Shopify admin panel
5. ✅ Identify API endpoints
6. ✅ Review GraphQL schema

### Week 3-4: Deep Dive Testing

**Focus Areas:**
- Authentication/authorization flows
- API endpoints (GraphQL, REST)
- Business logic flaws
- Injection vulnerabilities

**Daily Routine:**
1. Morning: Review new features/changelogs
2. Testing: Focus on one vulnerability type per day
3. Documentation: Document findings immediately
4. Evening: Research new attack techniques

### Week 5-6: Specialized Testing

**Amazon:**
- GenAI/LLM feature testing
- Mobile app reverse engineering
- Complex business logic flows

**Shopify:**
- Multi-tenant isolation testing
- Partner portal deep dive
- Webhook manipulation

### Week 7+: Report & Iterate

- Write detailed reports
- Submit findings
- Learn from feedback
- Test bypasses if fixes are incomplete

---

## 6. COMMON PITFALLS TO AVOID

### Amazon VRP:
❌ Testing AWS infrastructure
❌ Using 3rd party XSS Hunter
❌ Missing User-Agent string
❌ Exceeding 5 req/sec rate limit
❌ Testing against test/staging environments
❌ Post-exploitation activities
❌ Accessing other users' accounts

### Shopify:
❌ Testing live merchant stores
❌ Contacting Shopify Support
❌ Not using @wearehackerone.com email
❌ Testing stores you didn't create
❌ Public disclosure before resolution

### General:
❌ Submitting low-impact findings without PoC
❌ Not demonstrating security impact
❌ Duplicate reports
❌ Violating rate limits
❌ Social engineering attempts

---

## 7. REPORTING BEST PRACTICES

### Report Structure:
1. **Title:** Clear, concise vulnerability description
2. **Summary:** One-paragraph overview
3. **Affected Asset:** Proof it's in-scope
4. **Steps to Reproduce:** Numbered, detailed steps
5. **Proof of Concept:** Screenshots, video, code
6. **Impact:** Security impact assessment
7. **CVSS Score:** Calculated severity
8. **Remediation:** Suggested fix (optional but helpful)

### For Amazon GenAI Reports:
- Include: Timestamp, IP, Prompt String, Security Impact
- DO NOT include sensitive/explicit generated content

### Quality Checklist:
- [ ] Functional PoC included
- [ ] Clear security impact demonstrated
- [ ] Asset proven to be in-scope
- [ ] All reproduction steps work
- [ ] Screenshots/video provided
- [ ] CVSS score calculated
- [ ] No out-of-scope testing performed

---

## 8. ADVANCED TECHNIQUES

### GraphQL Security (Both Programs)
- Query depth attacks
- Field-level authorization testing
- Introspection abuse
- Batch query attacks
- N+1 query vulnerabilities

### JWT/Token Manipulation
- Algorithm confusion (none, HS256 → RS256)
- Key confusion attacks
- Token expiration bypass
- Signature verification bypass

### Race Conditions
- Payment processing
- Inventory management
- Account creation
- Privilege escalation

### Deserialization
- PHP object injection
- Java deserialization
- Python pickle
- .NET deserialization

### Server-Side Template Injection (SSTI)
- Template engine identification
- Payload crafting
- RCE via templates

---

## 9. LEARNING RESOURCES

### General Bug Bounty:
- HackerOne Hacktivity
- Bug Bounty Reports Explained (YouTube)
- PortSwigger Web Security Academy
- OWASP Top 10

### Program-Specific:
- Amazon VRP: Review accepted reports on HackerOne
- Shopify: Review their changelog and partner blog
- Both: Study their technology stack

### Tools & Techniques:
- Burp Suite documentation
- GraphQL security: OWASP GraphQL Cheat Sheet
- Mobile app security: OWASP Mobile Top 10

---

## 10. SUCCESS METRICS

### Short-term (First Month):
- ✅ Complete setup and recon
- ✅ Identify 10+ potential targets
- ✅ Submit 1-2 valid reports

### Medium-term (3 Months):
- ✅ Multiple accepted reports
- ✅ Understand program scope deeply
- ✅ Develop testing methodology

### Long-term (6+ Months):
- ✅ Consistent bug submissions
- ✅ High-severity findings
- ✅ Potential invitation to private programs (Amazon)
- ✅ Early Access Program (Shopify - if eligible)

---

## 11. DAILY CHECKLIST

### Morning:
- [ ] Check program updates/changelogs
- [ ] Review new in-scope assets
- [ ] Check for program announcements

### Testing Session:
- [ ] Verify User-Agent/email requirements
- [ ] Test only in-scope assets
- [ ] Follow rate limits
- [ ] Document findings immediately

### End of Day:
- [ ] Review findings
- [ ] Prioritize for reporting
- [ ] Research similar vulnerabilities
- [ ] Plan next day's focus

---

## FINAL RECOMMENDATIONS

1. **Start Small:** Begin with low-hanging fruit to understand the programs
2. **Read Reports:** Study accepted reports on HackerOne for both programs
3. **Stay Updated:** Programs evolve - check scope pages regularly
4. **Quality over Quantity:** One well-researched report > ten low-quality ones
5. **Follow Rules:** Violations can result in permanent bans
6. **Be Patient:** Bug bounty is a marathon, not a sprint
7. **Learn Continuously:** Security research is always evolving

---

**Remember:** Both programs value quality reports that demonstrate clear security impact. Focus on understanding the applications deeply rather than running automated scanners. Manual testing and creative thinking yield the best results.

Good luck with your bug hunting! 🐛💰

