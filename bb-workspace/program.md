# Bug Bounty Program — Target Definition

> Fill this out before starting any session. All stages read from this file.

## Program Info
- **Platform:** (HackerOne / Bugcrowd / Intigriti / private)
- **Program Name:**
- **Program URL:**
- **Started:** <!-- date you began -->
- **Program Type:** public / private
- **Response SLA:** First response: X days, Triage: X days, Bounty: X days

## Scope — In Scope
```
# Add domains, IPs, endpoints, apps
# Mark bounty eligibility per asset
# ASSET | TYPE | BOUNTY? | MAX_SEVERITY | NOTES
# *.example.com | WILDCARD | yes | critical |
# api.example.com | API | yes | critical | REST API docs at /swagger
# app.example.com | URL | yes | high | React SPA
```

## Scope — Out of Scope
```
# List explicitly excluded targets AND vulnerability types specific to this program
# admin.example.com — excluded domain
# *.staging.example.com — excluded domain
# CORS on api-public.example.com — explicitly OOS per program
# CSRF on like/favorite actions — explicitly OOS per program
```

## Vulnerability Types — Accepted
```
# e.g. XSS, SQLi, IDOR, RCE, SSRF, Auth bypass, Business logic
```

## Vulnerability Types — Excluded
```
# Copy EXACTLY from the program page — don't paraphrase
# e.g. Self-XSS, rate limiting on non-sensitive endpoints, clickjacking without impact
# Include specific exclusions like "2FA bypass on staging"
```

## Known Issues / Won't Fix (from program page)
```
# Issues the program has explicitly listed as known/accepted risk
# These will be closed as duplicate or informative if reported
# e.g. "IDOR on /api/users — known, under remediation"
```

## Previous Reports (yours + known)
```
# YOUR submitted reports — to avoid re-testing the same thing
# ID | Title | Status | Date | Notes
# 001 | XSS on login page | Resolved | 2026-01-15 | Fixed, don't retest
# 002 | IDOR on user history | Closed N/A | 2026-03-27 | API ignores userId param
```

## Reward Range
- Critical: $
- High: $
- Medium: $
- Low: $
- Informational: $0 / no reward

## Special Rules & Notes
```
# Any special instructions from the program
# e.g. "do not test payment flows in production"
# "add X-HackerOne-Research header to all requests"
# "do not contact support staff"
# "max 100 req/s"
```

## Test Credentials (if provided)
- **Username/Email:**
- **Password:**
- **Account type/role:**
- **Extra accounts:** <!-- for IDOR/privilege escalation testing -->
- **Test credit card:**
- **Disposable email provider:**
- **Credential expiry:** <!-- when do creds stop working? -->
- **Credential status:** ACTIVE / EXPIRED / UNKNOWN

## Tech Stack (fill during recon)
- **Frontend:**
- **Backend:**
- **Auth mechanism:** (session cookie / JWT Bearer / API key / OAuth / OIDC)
- **Identity provider:** (Cognito / Auth0 / Okta / custom / IdentityServer)
- **Infrastructure:** (AWS / GCP / Azure / Cloudflare / custom)
- **WAF:** (Cloudflare / AWS WAF / Akamai / none observed)
- **Protocol notes:** (HTTP/2 required for POST? / specific headers needed?)
- **CDN:**
- **Database:** (if known from errors/headers)

## Attack Surface Map (fill during recon)
```
# Discovered endpoints, subdomains, APIs
# HOST | TYPE | AUTH? | NOTES
# api.example.com | REST API | Bearer token | Swagger at /docs
# login.example.com | Identity server | N/A | OIDC, Duende IdentityServer
# portal.example.com | SPA | Session cookie | Angular, calls portal-api
# portal-api.example.com | Backend API | JWT | Only /v1/me and /v1/garages/*
```

## Defenses Observed (fill during testing)
```
# What security controls are in place?
# Cloudflare WAF — blocks XSS payloads in form-encoded POST bodies
# CSRF tokens — present on all forms
# Rate limiting — observed on /login (5 attempts then lockout)
# JWT signature validation — alg:none rejected
# Cognito Lambda triggers — block email attribute changes
```
