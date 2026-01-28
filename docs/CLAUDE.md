# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a bug bounty hunting workspace for program-specific security testing. Each subdirectory represents a separate bug bounty program with its own scope, rules, and testing guidelines.

## Directory Structure

The repository is organized by bug bounty program:
- `Amazon/` - Amazon Vulnerability Research Program (VRP) resources
- `Shopify/` - Shopify Bug Bounty Program resources

Each program directory contains:
- `Overview.md` - Complete program policy including scope, rules, severity guidelines, and eligible vulnerabilities

## Program-Specific Guidelines

### Amazon VRP

**Scope:**
- All retail marketplaces (wildcard `*.amazon`)
- Amazon retail iOS/Android apps (MShop)
- Subdomain takeovers on wildcard domains are IN-SCOPE

**Always Out of Scope:**
- Anything containing `aws` in subdomain
- Anything ending with `.a2z` or `*.dev`
- URLs with test/qa/integ/preprod/gamma/beta indicators
- AWS and AWS customer assets

**Testing Requirements (Amazon/Overview.md:121-133):**
- Use User-Agent string: `amazonvrpresearcher_yourh1username`
- Automated scanners limited to 5 requests/second with above User-Agent
- Create accounts using `yourh1username@wearehackerone.com`
- Do NOT use 3rd party sites for testing (e.g., XSS Hunter) - must use self-hosted infrastructure
- For subdomain takeovers: serve HTML file on hidden path with H1 username in HTML comment

**Severity Priorities (Amazon/Overview.md:182-202):**
- Critical: RCE, SQLi, XXE, XSS (high impact)
- High-Critical: SSRF
- Medium-High: Directory Traversal, Auth/Authz Bypass, IDOR, Privilege Escalation
- Low-Medium: CORS, CRLF, CSRF, Open Redirect, Request Smuggling

**GenAI/LLM Testing (Amazon/Overview.md:206-241):**
- Include: Timestamp, IP, Prompt String, Security Impact
- Prompt response content issues without security impact are OUT OF SCOPE
- DO NOT submit generated sensitive/explicit images
- Model hallucinations are out of scope

**Non-Eligible (Amazon/Overview.md:244-277):**
- Subdomain takeover on out-of-scope items
- Clickjacking, Self-XSS, Email Spoofing
- Missing security headers, cookie flags
- Minimal-impact CSRF (login/logout)
- Scanner outputs, DOS/DDOS, password complexity

### Shopify Bug Bounty

**Key Requirements (Shopify/Overview.md:24-32):**
- Must use `@wearehackerone.com` email alias for account creation
- Register via: https://partners.shopify.com/signup/bugbounty
- Test ONLY against stores you created
- Testing against live merchants is PROHIBITED

**Eligibility Rules (Shopify/Overview.md:34-40):**
- Reports must demonstrate functional proof of concept with security impact
- Rewards based on highest severity scenario that's plausible and linked to root issue
- Only reward when root cause is under Shopify's control
- IDOR evaluated based on identifier predictability and data sensitivity

**Bounty Calculation (Shopify/Overview.md:41-44):**
- Uses Shopify's Bug Bounty Calculator
- Minimum score > 0 for triage
- Score < 3 = $500 bounty
- Score >= 3 = calculated amount
- Bonuses for 0-score issues with high future impact (10% of estimated, $500-$5,000 range)

**Critical Rule (Shopify/Overview.md:60):**
- Do NOT contact Shopify Support about testing, program questions, or report updates - will result in disqualification and potential ban

**Testing Restrictions (Shopify/Overview.md:52-54):**
- Only test stores created with your HackerOne registered email
- Do not access or interact with stores you didn't create
- No public disclosure before resolution

## Workflow Recommendations

### Starting a New Program

1. Create a new directory named after the program
2. Add `Overview.md` with complete program policy from the platform
3. Document scope, out-of-scope items, testing rules, and severity guidelines

### Pre-Testing Checklist

1. Review `Overview.md` for the target program
2. Verify asset is explicitly in scope
3. Set up proper User-Agent strings if required
4. Create test accounts using program-approved email format
5. Configure scanning tools with rate limits per program requirements

### Report Preparation

When documenting findings, include:
- Target URL/asset and proof it's in scope
- Clear reproduction steps
- Functional proof of concept
- Security impact assessment
- Screenshots/video evidence
- Severity classification per program guidelines

## Important Security Testing Principles

**Do:**
- Only test assets explicitly listed in scope
- Use authorized testing accounts
- Follow rate limiting requirements
- Report vulnerabilities immediately upon validation
- Use self-hosted infrastructure for blind testing

**Don't:**
- Test out-of-scope assets or customer data
- Perform post-exploitation or excessive testing
- Access other users' accounts or data
- Use 3rd party services that expose vulnerability data
- Contact support channels as part of testing

## Notes

This workspace does not contain automated scanning tools or custom scripts. It serves as a centralized location for program-specific policies and testing guidelines. For automated testing, refer to the main bug bounty automation suite in the parent `bugbounty/` directory if available.
