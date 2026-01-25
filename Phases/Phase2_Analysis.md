# Phase 2: Analysis

**Goal:** Map the attack surface and identify potential entry points for testing.

---

## Overview

Analysis bridges reconnaissance and exploitation. This phase transforms raw data into actionable testing targets by understanding application workflows, identifying vulnerability candidates, and prioritizing testing efforts.

```
+-------------------+     +-------------------+     +-------------------+
|  Recon Data       | --> |  Analysis         | --> |  Testing Targets  |
+-------------------+     +-------------------+     +-------------------+
| - Subdomains      |     | - Workflow mapping|     | - IDOR candidates |
| - Endpoints       |     | - Auth analysis   |     | - SSRF vectors    |
| - Tech stack      |     | - Feature review  |     | - Logic flaws     |
| - APIs            |     | - Entry points    |     | - Priority list   |
+-------------------+     +-------------------+     +-------------------+
```

---

## Attack Surface Mapping

### 1. Categorize Discovered Assets

```markdown
## Asset Categories

### Critical (Test First)
- Authentication endpoints
- Payment processing
- Admin panels
- API endpoints with data access

### High Priority
- User data management
- File upload features
- Search functionality
- Webhook configurations

### Medium Priority
- Static content
- Public information pages
- Marketing sites

### Low Priority / Skip
- CDN assets
- Third-party widgets
- Out-of-scope domains
```

### 2. Create Asset Inventory

```markdown
| Asset | Type | Auth Required | Data Sensitivity | Priority |
|-------|------|---------------|------------------|----------|
| api.target.com | API | Yes | High | Critical |
| admin.target.com | Panel | Yes | Critical | Critical |
| checkout.target.com | Payment | Yes | Critical | Critical |
| search.target.com | Feature | No | Low | High |
| blog.target.com | Content | No | None | Low |
```

---

## Workflow Analysis

### Authentication Flow Mapping

```
+----------+     +----------+     +----------+     +----------+
|  Login   | --> |   2FA    | --> | Session  | --> | Dashboard|
+----------+     +----------+     +----------+     +----------+
     |               |                |                |
     v               v                v                v
 [Username]     [OTP Code]      [Session ID]    [User Data]
 [Password]     [Backup]        [Token]         [Actions]
                [Recovery]
```

**Questions to Answer:**
- Can any step be skipped?
- Are tokens properly validated?
- Is session bound to user?
- Can 2FA be bypassed?

### Multi-Step Process Analysis

For any multi-step workflow:

```markdown
## Workflow: [Process Name]

### Steps
1. Step 1 - [Description] - Endpoint: /api/step1
2. Step 2 - [Description] - Endpoint: /api/step2
3. Step 3 - [Description] - Endpoint: /api/step3

### State Management
- [ ] Client-side state (modifiable?)
- [ ] Server-side validation at each step?
- [ ] Can steps be reordered?
- [ ] Can steps be skipped?

### Testing Ideas
- [ ] Skip step 2, go directly to step 3
- [ ] Modify state between steps
- [ ] Replay earlier steps after completion
```

---

## Vulnerability Candidate Identification

### IDOR Candidates

Look for endpoints with resource identifiers:

```markdown
## IDOR Analysis

### Identified Parameters
| Endpoint | Parameter | Type | Data Access |
|----------|-----------|------|-------------|
| /api/users/{id} | id | Integer | User profile |
| /api/orders/{uuid} | uuid | UUID | Order details |
| /api/files/{hash} | hash | Hash | File download |
| /api/accounts?id= | id | Query | Account data |

### Testing Priority
1. /api/orders/{uuid} - Financial data (HIGH)
2. /api/users/{id} - PII access (HIGH)
3. /api/files/{hash} - Document access (MEDIUM)
```

### SSRF Candidates

Find features accepting URLs:

```markdown
## SSRF Analysis

### URL Input Features
| Feature | Endpoint | Input Type | Validation |
|---------|----------|------------|------------|
| Webhook | /api/webhooks | POST body | Unknown |
| Image import | /api/import/image | Query param | Unknown |
| PDF export | /api/export/pdf | POST body | Unknown |
| Preview | /api/preview | Query param | Unknown |

### Testing Priority
1. Webhook - Direct URL input (HIGH)
2. Image import - May bypass filtering (HIGH)
3. PDF export - Server-side rendering (MEDIUM)
```

### Business Logic Candidates

```markdown
## Business Logic Analysis

### E-commerce Flows
- [ ] Add to cart -> Modify price?
- [ ] Apply discount -> Remove item -> Discount persists?
- [ ] Checkout flow -> Skip payment?
- [ ] Quantity -> Negative values?
- [ ] Coupon stacking?

### User Management
- [ ] Profile update -> Change other user's data?
- [ ] Email change -> Verification bypass?
- [ ] Password reset -> Token reuse?
- [ ] Account deletion -> Data retention?

### Financial Operations
- [ ] Balance transfer -> Race condition?
- [ ] Refund processing -> Double refund?
- [ ] Currency conversion -> Rounding errors?
```

### Subdomain Takeover Candidates

```markdown
## Subdomain Takeover Analysis

### CNAME Records Pointing to Services
| Subdomain | CNAME Target | Service | Status |
|-----------|--------------|---------|--------|
| shop.target.com | shops.myshopify.com | Shopify | Active |
| docs.target.com | target.github.io | GitHub | 404 Error |
| cdn.target.com | d1234.cloudfront.net | CloudFront | Active |

### Potential Takeovers
1. docs.target.com - GitHub Pages not configured (HIGH)
```

---

## API Analysis

### GraphQL Schema Review

```bash
# Get schema via introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"}'
```

**Analysis Points:**
- Available queries and mutations
- Sensitive fields exposed
- Authorization on operations
- Nested query potential

### REST API Mapping

```markdown
## API Endpoint Map

### User Operations
- GET /api/users/{id} - Get user (Auth: Token)
- POST /api/users - Create user (Auth: None)
- PUT /api/users/{id} - Update user (Auth: Token)
- DELETE /api/users/{id} - Delete user (Auth: Token)

### Order Operations
- GET /api/orders - List orders (Auth: Token)
- GET /api/orders/{id} - Get order (Auth: Token)
- POST /api/orders - Create order (Auth: Token)

### Admin Operations (if accessible)
- GET /api/admin/users - List all users
- POST /api/admin/config - Update config
```

---

## Priority Matrix

### Scoring Criteria

| Factor | Weight | Description |
|--------|--------|-------------|
| Data Sensitivity | 3x | PII, financial, credentials |
| Auth Level | 2x | No auth > User > Admin |
| Functionality | 2x | Write > Read operations |
| Exposure | 1x | Public > Internal |

### Priority Calculation

```
Priority Score = (Data × 3) + (Auth × 2) + (Func × 2) + (Exposure × 1)

Example:
- /api/users/{id} (GET user profile)
  Data: 4 (PII) × 3 = 12
  Auth: 3 (User token) × 2 = 6
  Func: 2 (Read) × 2 = 4
  Exposure: 4 (Public API) × 1 = 4
  Total: 26 (HIGH)
```

---

## Output Templates

### Attack Surface Document

```markdown
# Attack Surface Analysis: [Target]
Date: [YYYY-MM-DD]

## Executive Summary
- Total assets discovered: X
- Critical priority targets: Y
- High priority targets: Z

## Vulnerability Candidates

### IDOR (X candidates)
1. [Endpoint] - [Risk] - [Priority]

### SSRF (X candidates)
1. [Feature] - [Risk] - [Priority]

### Business Logic (X candidates)
1. [Flow] - [Risk] - [Priority]

### Other (X candidates)
1. [Type] - [Risk] - [Priority]

## Testing Order
1. [Target 1] - [Reason]
2. [Target 2] - [Reason]
3. [Target 3] - [Reason]

## Notes for Phase 3
- [Important observation 1]
- [Important observation 2]
```

### Target Worksheet

```markdown
# Target Worksheet: [Endpoint/Feature]

## Basic Information
- URL:
- Method:
- Auth Required:
- Technology:

## Parameters
| Name | Type | Location | Validation |
|------|------|----------|------------|
| | | | |

## Observations
-

## Test Cases
- [ ] Test case 1
- [ ] Test case 2
- [ ] Test case 3

## Findings
-
```

---

## Analysis Checklist

### Authentication & Authorization
- [ ] Map all authentication endpoints
- [ ] Identify authorization mechanisms
- [ ] Document session management
- [ ] Note 2FA/MFA implementation
- [ ] Check for password reset flows

### Data Flow
- [ ] Identify sensitive data endpoints
- [ ] Map data input points
- [ ] Track data through application
- [ ] Note encryption usage
- [ ] Check for data exposure

### Business Logic
- [ ] Document core workflows
- [ ] Identify state transitions
- [ ] Note multi-step processes
- [ ] Find financial operations
- [ ] Map user interactions

### API Surface
- [ ] Catalog all API endpoints
- [ ] Document authentication per endpoint
- [ ] Note parameter types
- [ ] Check for GraphQL introspection
- [ ] Identify rate limiting

### Vulnerability Mapping
- [ ] List IDOR candidates
- [ ] List SSRF candidates
- [ ] List business logic candidates
- [ ] Check subdomain takeover status
- [ ] Note exposed files/secrets

---

## Next Phase

Once analysis is complete, proceed to [Phase 3: Exploitation](Phase3_Exploitation.md) to test identified vulnerability candidates.
