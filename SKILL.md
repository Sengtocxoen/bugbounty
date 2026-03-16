---

Security Audit Skill — Team Reference  
 Skill name: security-audit  
 Version: 9-phase + RAG (v2)  
 Invoke: /security-audit <target-path> [output=<report-dir>]

---

What It Does

Runs Claude as a hostile attacker — not a code reviewer — against a codebase or file. Produces structured findings with full taint chains, sanitizer  
 bypass proof, PoC commands, 0–100 confidence scores, and CVSS estimates. Filters to CVE-class findings only (no noise).

Mindset the skill operates under:
▎ Every assumption the developer made is a hypothesis to falsify. Every security control is a hypothesis — find the input it did not consider. Treat  
 every function boundary, every data transformation, and every implicit trust relationship as a potential exploit primitive.

---

How to Run It

# Inline output (small repos)

/security-audit ./src

# Save each phase as a separate markdown file

/security-audit ./src output=./audit-reports

# Single file focus

/security-audit ./src/api/payments.ts

---

Full Methodology — 9 Phases

Pre-Phase: Read Documentation First

Before touching code — read README, API specs, OpenAPI/Swagger, architecture docs. Developer docs reveal the intended security model. Every gap between
intended and actual behavior is a candidate finding.

---

Large Codebase Mode (RAG — activate for repos >40 files or >3000 LOC)

Do NOT read all files into context. Use targeted retrieval instead:

┌───────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐  
 │ RAG Step │ What It Does │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 1 — Structure │ Glob-only pass: map directory layout, count files, identify routes/middleware/workers/infra. Zero file reads. │  
 │ Mapping │ │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 2 — Entry Point │ Framework-specific grep patterns to list all HTTP routes + handler names without reading implementations. Covers │  
 │ Extraction │ Express, NestJS, FastAPI, Flask, GraphQL SDL, Spring, Rails, Go gin/chi, Django. │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 3 — Security Control │ Grep for auth/rate-limit/CSRF/CORS/validation declarations. Cross-reference with routes to produce endpoint → [auth, │
 │ Mapping │ rate_limit, csrf, validated] map. │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 4 — Sink-First │ Grep for dangerous patterns (SQLi, shell exec, SSRF, XXE, mass assignment, eval, queue dispatch). Read only ±20 │  
 │ Scanning │ lines around each match. │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 5 — │ From a suspicious endpoint, grep for each called function's definition. Follow the call chain to sink or sanitizer. │  
 │ Follow-the-Symbol │ Never read files outside the chain. │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 6 — Infrastructure │ Always fully read: docker-compose.yml, Dockerfile, .env, k8s/_.yaml, terraform/_.tf, .github/workflows/\*.yml. Small │  
 │ Fast Scan │ files, frequent Critical findings. │  
 ├───────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤  
 │ Step 7 — Archetype Batch │ Run all 32 Phase 9 grep patterns upfront in severity order. Read context only for matches that survive the auth map │  
 │ Scan │ cross-reference. │  
 └───────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

Reading budget rules:

- Full read: route files, middleware, config files, infrastructure files
- Targeted read: service/repository files (only functions in call chain)
- Grep only: model/entity files (field names), migration files (schema)
- Never read: node_modules, vendor, dist, build, generated files
- Hard limit: after 15 full-file reads with no Critical/High finding → switch to grep-only mode

---

Phase 1 — Threat Modeling & Component Isolation

1A. Source Taxonomy — 15 categories of attacker-controlled data:

┌─────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Category │ Examples │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ HTTP Request Structure │ Path params, query strings, JSON body, headers (X-Forwarded-For, Origin, Authorization), cookies, multipart │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ URL Routing & Path Handling │ Route params, wildcard routes, path normalization, double-encoding, proxy-forwarded paths │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Search & Filter Parameters │ query, orderBy, sortBy, cursor, offset, limit — flow directly into ORM query builders │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Cursor/Pagination Tokens │ Base64-decoded cursors, JWT-like pagination tokens — attacker controls decoded content │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ GraphQL Operations │ Query args, mutation inputs, subscription filters, nested resolver args, introspection │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ OAuth / SSO │ state, redirect_uri, PKCE code_challenge, SAML assertions, id_token claims, nonce │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Blockchain/Chain Data │ On-chain events, extrinsic args, decoded SCALE types │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Environment & Config │ process.env, .env, YAML/TOML configs, feature flags │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Inter-Process / Queue │ BullMQ/RabbitMQ/SQS payloads, WebSocket messages, gRPC deserialization │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Database Re-read │ DB values, Redis cache, session store entries (second-order injection vector) │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ External Fetches │ Third-party API responses, webhook payloads, OAuth callbacks, IPFS/HTTP metadata │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ File System │ Uploaded files, user-controlled paths, ZIP archives, XML files (DOCX, SVG, XLSX) │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Deployment / Infrastructure │ docker-compose, Dockerfile, k8s manifests, Terraform, CI/CD pipelines │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Admin Dashboards │ Bull Board, pgAdmin, Hasura Console, Swagger UI, /debug, /metrics, /health │
├─────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Cross-Platform Sources │ Mobile deep links, IPC channels, smart contract calldata, firmware serial input │
└─────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

1B. Sink Categories:
Code execution, Shell execution, Deserialization, XXE, SQL/ORM injection, Mass assignment, Prototype pollution, File system, Template rendering,  
 Redirects, Cryptography misuse, SSRF, Queue dispatch

1C. Security Boundaries per route:
Auth gate, CSRF protection, Authorization checks, Rate limiting, Input validation layer, GraphQL complexity limits, CORS configuration, HTTP method  
 override controls

1D. Priority Matrix: ranked by (unauthenticated surface) × (sink severity) × (data flow complexity)

---

Phase 2 — Deep Data-Flow Mapping

Tracks how data transforms between function boundaries — the landscape before formal taint chains.

- Function-level parameter tracing: where does each parameter actually come from (not just "from user input")
- How HTTP request structure influences execution (routing dispatch, query parameter injection, content-type confusion)
- How search/filter parameters flow through the query builder chain
- How cursor/pagination data is decoded and used

Implicit Trust Boundaries to challenge:

┌──────────────────────────────────────────┬────────────────────────────────────────────────┐
│ Assumption │ Risk │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "It came from our DB, so it's safe" │ Second-order SQLi │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "Blockchain data is consensus-validated" │ Malicious contract emits crafted events │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "Internal queue messages are trusted" │ Queue poisoning if Redis is accessible │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "The ORM handles escaping" │ Column names can't be parameterized │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "Enum validates the input" │ Enum value may be raw SQL string used directly │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "Validators check the input" │ One field validated, others unchecked │
├──────────────────────────────────────────┼────────────────────────────────────────────────┤
│ "It passed OAuth, so user data is safe" │ JWT claims need re-validation before use │
└──────────────────────────────────────────┴────────────────────────────────────────────────┘

---

Phase 3 — Source-to-Sink Taint Tracking

For every high-priority path, documents the full taint chain:

SOURCE: [method / query / chain event / queue job]
auth='[level]' csrf=[on/off] rate_limit=[on/off]
param: name = <ATTACKER CONTROLLED>
origin: [direct input / decoded cursor / DB re-read / chain event / OAuth claim]
↓ function1() — transforms, validation
↓ sanitizer_check() ← BYPASS ANALYSIS
↓ function2() — trust_boundary_crossed: [YES/NO]
SINK: dangerous_operation() → IMPACT

Verdict: EXPLOITABLE / CONDITIONAL / BLOCKED

Sanitizer Bypass Analysis — for every sanitizer in the chain, evaluates:

┌────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────┐
│ Sanitizer │ Bypass Techniques │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Regex/pattern │ Unicode normalization, null bytes, newline injection, double encoding, overlong UTF-8, ReDoS │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ File extension │ Double extension, null byte termination, MIME sniffing mismatch, trailing dots on Windows │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Path traversal filter │ ../, %2e%2e%2f, absolute path, Windows ..\\, UNC paths, symlink race │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Allowlist filter │ Substring vs full-string match, prepend/append bypass, case sensitivity │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Length check │ Off-by-one, Unicode code points vs bytes, truncation-after-validation │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Signature/HMAC │ Empty secret key, timing attack, RS256→HS256 confusion, missing exp/nbf │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Enum validation │ Raw string passthrough to SQL, GraphQL strict enforcement check │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ class-validator │ Is @Validate() actually called? whitelist: true? Nested objects validated? │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Parameterized query │ Column/table names cannot be parameterized — only values can │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
│ Prototype pollution filter │ URL-encoded **proto**, unicode variants, nested bypass │
└────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────┘

Type Confusion Analysis — at every API boundary: wrong types (array instead of int, NaN, Infinity, BigInt overflow, missing 0x prefix on hex strings).

---

Phase 4 — Assumption Failure Hunting

4A. Race Conditions (TOCTOU): check → gap → use pattern. Multi-step workflows, non-atomic read-modify-write, double-spend, file-based TOCTOU,
blockchain chain reorg double-processing, queue job ID dispatch race.

4B. Business Logic Flaws: state machine abuse, negative/zero/MAX price manipulation, IDOR (sequential IDs, UUID v1 predictability, MD5-based IDs),  
 privilege parameter injection, workflow bypass, pagination abuse, search wildcard abuse, HTTP method override, rate limit IP bypass via header
spoofing, API version downgrade.

4C. Cryptographic Mishandling: IV/nonce reuse, ECB mode, weak KDF, predictable randomness, JWT confusion (alg:none, RS256→HS256, kid SQLi/path
traversal, jku/x5u SSRF), timing oracle, padding oracle (CBC error message differentiation), signature replay, key exposure, hash collision in dedup.

4D. Second-Order & Stored Injection: store-then-use patterns across requests, blockchain event data → DB → raw SQL, metadata URI SSRF.

4E. Denial of Service: GraphQL complexity, ReDoS, unbounded payloads, N+1 query amplification, queue flooding, memory exhaustion.

4F. Dependency & Supply Chain: CVE'd packages, unpinned deps, user-controlled dependency sources, lockfile integrity.

4G. Prototype Pollution: \_.merge(), deepmerge(), recursive copy with **proto** keys → auth bypass or RCE via Pug/lodash template gadgets. Test
payloads: {"**proto**": {"isAdmin": true}}.

---

Phase 5 — Compound Vulnerability Chaining

Two medium findings that chain = one Critical. Common chains:

- SSRF + IMDSv1 → cloud credential theft → account takeover
- GraphQL query injection + stored data → full user data extract
- Cursor injection + SQL column reference → arbitrary data extraction
- Queue poisoning + job handler trust → code execution in worker
- Open redirect + OAuth → token hijack → account takeover
- Rate limit bypass + brute force → credential stuffing
- Error message info leak + SQLi → DB structure discovery → targeted extraction
- CORS origin reflection + stored XSS → cross-origin session token exfiltration
- Prototype pollution + eval/template sink → RCE via gadget (Pug outputFunctionName)
- Mass assignment + privilege check → role=admin persisted → all auth checks bypass
- API version downgrade + missing auth → v1 exposes data protected by v2

---

Phase 6 — PoC Engineering & Verification

6A. Minimum reproducible PoC — exact curl, Python, or GraphQL query.

6B. Per-class PoC search strategy:

┌─────────────────────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Vuln Class │ Strategy │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ SQL Injection │ Identify SQL context → DB engine → time-based blind (pg_sleep) → UNION SELECT → data extract │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ GraphQL │ Introspection → type confusion → complexity (nested fragments/aliases) → batch → mutation auth bypass │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ SSRF │ External canary → 169.254.169.254 → file:/// → DNS rebinding → redirect bypass │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Race Condition │ 50+ parallel requests via asyncio → measure double-spend rate over 100 attempts │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Auth Bypass │ Unauthenticated → expired token → horizontal IDOR → vertical PrivEsc → parameter manipulation │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DoS │ Minimal payload → measure response time baseline vs attack (>10x = confirmed) │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Cursor/Pagination Injection │ Decode base64 → modify id/orderValue → test column name injection → error-based extract │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Prototype Pollution │ ?**proto**[x]=polluted → confirm in response → find gadget → escalate │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ XXE │ XML upload endpoint → <!ENTITY xx SYSTEM "file:///etc/passwd"> → in-band vs OOB │
├─────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Mass Assignment │ Add role, isAdmin, price, ownerId to create/update → check if persisted │
└─────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────┘

6C. Sanitizer-targeted payload set (7 variants: base, encoded, unicode, type confusion, edge case, second-order stored, chain context).

6D. Exploit simulation — what does the attacker actually achieve? Reliability? Preconditions?

---

Phase 7 — Confidence Scoring & Blast-Radius Triage

Every finding gets a 0–100 confidence score:

┌────────┬───────────────────────────────────────────────────────┐
│ Score │ Meaning │
├────────┼───────────────────────────────────────────────────────┤
│ 90–100 │ Confirmed Exploitable — ready to submit │
├────────┼───────────────────────────────────────────────────────┤
│ 75–89 │ High Confidence — needs live verification only │
├────────┼───────────────────────────────────────────────────────┤
│ 50–74 │ Medium Confidence — worth investigating further │
├────────┼───────────────────────────────────────────────────────┤
│ 25–49 │ Low Confidence — investigate if time permits │
├────────┼───────────────────────────────────────────────────────┤
│ 0–24 │ Informational — code smell, not currently exploitable │
└────────┴───────────────────────────────────────────────────────┘

Scoring formula:
Confidence = (Taint_Completeness × 0.30) + (Sanitizer_Bypass_Proof × 0.25) + (Impact_Severity × 0.20) + (Precondition_Feasibility × 0.15) + (PoC_Reproducibility × 0.10)

Finding Verdict Card includes: confidence sub-scores, severity, category, auth required, file:line, full taint chain, data source origin, sanitizer  
 bypass proof, PoC, verification steps, exploit simulation, conditions required, impact, compound chain potential, CVSS estimate, bounty tier.

---

Phase 8 — Iterative Deepening Loop

After Phases 1–7:

- 8A. Gap Analysis — explicitly list attack vectors not explored, source categories not traced, sanitizers accepted without bypass attempt, archetypes
  not checked
- 8B. Pattern Expansion — does the found pattern repeat elsewhere? Is there a more impactful variant? A lower-precondition variant?
- 8C. Cross-Component Analysis — GraphQL resolver → queue worker, chain event → DB → response, external metadata → DB → raw SQL
- 8D. Iterate — repeat Phases 2–7 until confidence scores stabilize
- 8E. Skill Growth — after each audit, search web for new patterns to add to Phase checklists and Archetype Library (improves the methodology, not the
  current target findings)

---

Phase 9 — Vulnerability Archetype Library

32 reusable detection patterns consulted from Phase 1 onwards:

┌─────┬─────────────────────────────────────────┬────────────────────────────────────────────────────────────┐
│ # │ Archetype │ Detection │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A1 │ Enum-to-SQL passthrough │ grep orderBy|groupBy|addSelect → trace to enum def │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A2 │ Infrastructure metadata over-permission │ Hasura/proxy config → role: public, empty filter │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A3 │ Incomplete sanitizer │ Read every safe*/sanitize* → test all vuln classes │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A4 │ Dead security code │ grep security declarations → verify each is wired │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A5 │ Unauthenticated queue dispatch │ grep dispatch|addJob|enqueue → check auth │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A6 │ SSRF via stored URIs │ grep fetch|axios → check URL source → DNS rebinding │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A7 │ Queue payload trust │ Check every queue consumer: is job.data re-validated? │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A8 │ Decode function DoS │ grep decode|JSON.parse → verify try/catch at boundary │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A9 │ ORM proxy public role │ Hasura/PostGraphile config → verify row-level filters │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A10 │ Pagination unbounded │ Test limit: 999999, decode+modify cursors │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A11 │ TOCTOU validation gap │ Search for check → await → use patterns │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A12 │ Second-order stored injection │ Trace every DB read to raw queries/HTML/commands │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A13 │ GraphQL complexity abuse │ Check maxDepth, maxComplexity config │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A14 │ Signature replay │ Check every verify* call for nonce/timestamp │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A15 │ Unauthenticated admin dashboard │ grep bull-board|swagger-ui → check auth before route │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A16 │ Exposed Docker ports │ docker-compose ports: → check 0.0.0.0 bindings │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A17 │ Dev mode in production │ grep dev_mode|DEBUG|verbose → check env gating │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A18 │ Destructive env var trigger │ grep TRUNCATE|DROP|RESET|WIPE in config │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A19 │ Missing error handling │ Count catch blocks vs handler count → if low, systemic │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A20 │ Error message info leakage │ grep error.message|error.stack in response handlers │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A21 │ Crypto key gen without auth │ grep generateKey|getPrivateKey → check auth │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A22 │ Exception-swallowing security filter │ Read every filter catch block → verify it throws/rejects │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A23 │ Reflection-based deserialization │ grep setAccessible|Class.forName → trace type input │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A24 │ Unbounded in-memory maps │ grep ConcurrentHashMap|HashMap → check eviction │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A25 │ Mass assignment │ grep .create(req|assign.*body → check allowlist │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A26 │ CORS origin reflection │ grep allowedOrigins|cors( → check if Origin echoed │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A27 │ API version downgrade │ grep v1|v2 in routes → compare auth/validation per version │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A28 │ Webhook signature bypass │ grep webhook.\*signature|verifyWebhook → test empty secret │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A29 │ JWT kid/jku header injection │ Decode JWT → check kid in DB lookup or file path │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A30 │ Theme/template path injection │ grep writeFile|readFile → check if path from server key │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A31 │ Prototype pollution via deep merge │ grep \_.merge|deepmerge → test **proto** → find gadget │
├─────┼─────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ A32 │ XXE via file upload │ grep multer|upload → check XML MIME types → test SVG │
└─────┴─────────────────────────────────────────┴────────────────────────────────────────────────────────────┘

---

32 Operating Rules

1. Never accept a sanitizer as blocking without attempting at least 3 bypass techniques
2. Assume all data is malicious
3. Config-dependent vulnerabilities are valid (empty webhook secret = real finding)
4. Compound chains count — two mediums that reach critical = one Critical
5. Always provide a PoC — no PoC = not reportable
6. Simulate the full exploit — "there is an injection point" is not enough
7. Deprioritize noise — no RCE/PrivEsc/Data Exfil/hard DoS = Low/Info
8. Type confusion is a first-class check at every API boundary
9. Crypto findings require implementation analysis, not just algorithm name
10. Second-order sinks are in scope — trace through storage and retrieval
11. Data doesn't only come from "user input" — trace all 15 source categories
12. Every finding gets a 0–100 confidence score
13. Iterate until coverage is complete — one pass is never enough
14. Always audit infrastructure metadata files
15. Trace enum definitions to their SQL usage
16. Read every custom sanitizer line-by-line
17. Map all queue dispatch endpoints
18. Test decode functions at API boundaries for uncaught exception DoS
19. Web research improves the methodology, not the current target findings
20. Check for dead security code — declared but never wired
21. Always analyze deployment configs
22. Audit every admin dashboard
23. Count try/catch blocks vs resolver count — low ratio = systemic missing error handling
24. Review every error response for raw error.message / error.stack leakage
25. Treat environment variables as attack surface
26. After each pass, explicitly list what you did NOT look at — then audit one of those things
27. Read documentation before code
28. Always test CORS — reflected origin + credentials = account takeover
29. Test mass assignment on every create/update endpoint
30. Prototype pollution is first-class — find the gadget, not just the injection point
31. Document negative findings explicitly — proves coverage, prevents re-investigation
32. Check HTTP method override (X-HTTP-Method-Override, \_method)

---

Output Format

Each finding is a self-contained Verdict Card containing:

Finding N — [Title]
Confidence Score: [0-100] with sub-score breakdown
Severity / Category / Auth Required / File:Line / In-scope
Taint Chain: SOURCE → transforms → sanitizers → SINK
Data Source Origin (exactly where attacker-controlled data comes from)
Why It's Real (explicit sanitizer-by-sanitizer dismissal)
Sanitizer Bypass Proof (exact payload)
PoC (curl / Python / GraphQL)
PoC Verification Steps
Exploit Simulation (what attacker achieves post-exploitation)
Conditions Required
Impact
Compound Chain Potential
Verdict: Exploitable / Conditional / Reliability / CVSS / Bounty tier / Next step
