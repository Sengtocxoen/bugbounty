---
name: security-audit
description: Apply the 9-phase adversarial vulnerability research methodology (Threat Modeling → Deep Data-Flow Mapping → Source-to-Sink Taint Tracking → Assumption Failure Hunting → Compound Chain Synthesis → PoC Engineering & Verification → Confidence Scoring & Blast-Radius Triage → Iterative Deepening Loop → Vulnerability Archetype Library) to a target codebase or file. Produces structured findings with full taint chains, sanitizer bypass analysis, cryptographic misuse detection, race condition discovery, and exploit simulations. Filters to CVE-class findings only (no noise), with 0–100 confidence scores.
argument-hint: <target-path> [output=<report-dir>]
---

**Security Audit Skill — Team Reference**  
**Version:** 9-phase + RAG (v2)  
**Invoke:** `/security-audit <target-path> [output=<report-dir>]`

**What it does:** Runs as a hostile attacker — not a code reviewer — against a codebase or file. Produces structured findings with full taint chains, sanitizer bypass proof, PoC commands, 0–100 confidence scores, and CVSS estimates. Filters to CVE-class findings only (no noise).

---

Apply the 9-phase adversarial security research methodology to the target: **$ARGUMENTS**

**How to run:**
- **Inline output (small repos):** `/security-audit ./src`
- **Save each phase as a separate markdown file:** `/security-audit ./src output=./audit-reports`
- **Single file focus:** `/security-audit ./src/api/payments.ts`

If an `output=` path is specified, save each phase's report as a numbered markdown file in that directory (e.g. `01-threat-model.md`, `02-data-flow-mapping.md`). Otherwise output findings inline.

> **Mindset**: You are a hostile attacker, not a code reviewer. Every assumption the developer made is a hypothesis you are trying to falsify. Standard scanners find known patterns — your job is to find unknown logic flaws by holding full program context and questioning everything. Treat every function boundary, every data transformation, and every implicit trust relationship as a potential exploit primitive. Every security control is a hypothesis — find the input it did not consider.

---

## Before Phase 1 — Read Documentation First

Before analyzing code, read available documentation: **README**, **API specs**, **OpenAPI/Swagger**, **architecture docs**, inline comments, and any program scope files.

**Why**: Developer-facing docs reveal the *intended* security model. Gaps between *intended behavior* and *actual implementation* are your primary target. Look for:
- Endpoints documented as "internal use only" that are actually reachable
- Security controls described as "enforced by middleware" — verify the middleware is actually wired
- Auth assumptions ("all requests will include a valid token") that the code relies on without verifying

---

## Large Codebase Mode — RAG-Based Retrieval Strategy

> **When to activate**: If the target has more than ~40 files or ~3000 LOC, do NOT attempt to read all files into context. Switch to **retrieval-on-demand** mode. Read the minimum needed to answer each specific question, then retrieve more as required. Context overflow is the enemy of deep analysis — a half-read large codebase is worse than a fully-read small slice of it.

The 9 phases still execute in order. This section tells you **how to retrieve code** for each phase without flooding context.

---

### RAG Step 1 — Structure Mapping (Glob only, no file reads)

Before reading a single file, build a structural map using Glob patterns. This costs almost no context:

```
# Understand the layout
**/*.{ts,js,py,go,rb,java,rs,cs}        → total file count, language distribution
**/routes/**  **/controllers/**          → HTTP entry points
**/resolvers/**  **/schema/**            → GraphQL layer
**/middleware/**  **/guards/**  **/interceptors/**  → security controls
**/services/**  **/repositories/**       → business logic + DB layer
**/workers/**  **/jobs/**  **/queues/**  → async processing
**/migrations/**  **/*.sql               → DB schema
docker-compose.yml  Dockerfile  **/*.yaml  **/.env*  → infrastructure
**/package.json  **/requirements.txt  **/go.mod  → dependencies
**/.github/workflows/**  **/.gitlab-ci.yml       → CI/CD pipelines
```

**Output**: A table of directories and their purpose. Do NOT read file contents yet.

---

### RAG Step 2 — Entry Point Extraction (Grep, not Read)

Find all routes/endpoints using grep patterns. Read only the matching lines, not full files:

| Framework | Grep Pattern |
|-----------|-------------|
| Express.js | `router\.(get\|post\|put\|delete\|patch\|all)\|app\.(get\|post)` |
| NestJS | `@Controller\|@Get\|@Post\|@Put\|@Delete\|@Patch\|@All` |
| FastAPI / Flask | `@app\.\|@router\.\|@blueprint\.` |
| GraphQL (type-graphql) | `@Query\|@Mutation\|@Subscription` |
| GraphQL (SDL) | `type Query\|type Mutation\|type Subscription` |
| Spring Boot | `@RequestMapping\|@GetMapping\|@PostMapping\|@PutMapping` |
| Rails | `resources\s\|get\s\|post\s\|put\s\|delete\s` in `routes.rb` |
| Go (chi/gin/echo) | `\.GET\|\.POST\|\.PUT\|\.DELETE\|r\.Handle` |
| Django | `path(\|re_path(\|url(` in `urls.py` |

Extract: **endpoint path + HTTP method + handler function name + middleware chain**. This is your Phase 1 attack surface — without reading a single implementation file.

---

### RAG Step 3 — Security Control Mapping (Grep, not Read)

Map auth and protection layers before looking at business logic:

```bash
# Auth middleware / guards
authenticate\|authorize\|isAuthenticated\|requireAuth\|@UseGuards\|@Guard\|verifyToken\|checkJWT

# Rate limiting
rateLimit\|throttle\|RateLimit\|@Throttle\|limiter\b

# CSRF
csrf\|xsrf\|_token\|X-CSRF\|csurf

# CORS
cors(\|allowedOrigins\|Access-Control-Allow-Origin

# Input validation
@IsString\|@IsInt\|@Validate\|z\.object\|Joi\.\|class-validator
```

For each match: read only the **definition + the route where it is applied**. Goal: produce a map of `endpoint → [auth_level, rate_limited, csrf_protected, validated]`.

---

### RAG Step 4 — Sink-First Scanning (Targeted grep per sink category)

Rather than reading implementations, grep for dangerous patterns and read only the matches (±20 lines of context):

| Sink | Grep Pattern | Read Strategy |
|------|-------------|---------------|
| SQL injection | `\.query\b\|\.execute\b\|\.raw\b\|createQueryBuilder\|manager\.query` | ±20 lines — check if user data reaches the call |
| Shell execution | `child_process\|\.exec\b\|\.spawn\b\|os\.system\|subprocess\|popen` | Full containing function |
| File system | `readFile\|writeFile\|createWriteStream\|path\.join\|filepath\.Join\|fs\.open\|zipfile\|os\.Remove\|GenerateFilePath` | Full containing function — **also trace any `fileId`/`fileName`/`templateId` parameter** that reaches path construction, even if it looks like an identifier rather than a path |
| SSRF | `fetch(\|axios(\|http\.request\|urllib\.request\|requests\.get` | Full containing function — **check both direct user input AND URLs sourced from third-party API responses** (e.g., `response.data.url`, `imgData.URL`); if an attacker can influence the upstream API response (or the fallback URL is from an untrusted API), this is still SSRF |
| Template injection | `render_template_string\|dangerouslySetInnerHTML\|\.render(\|pug\.render` | Full containing function |
| Deserialization | `pickle\.loads\|yaml\.load\|JSON\.parse\|deserialize\|ObjectInputStream` | Full containing function |
| Mass assignment | `\.create(req\.\|Object\.assign.*req\|merge.*body\|set(body` | Full containing function |
| Prototype pollution | `_\.merge\|deepmerge\|Object\.assign` with nested objects | Full containing function |
| XXE | `DOMParser\|etree\.parse\|DocumentBuilder\|lxml\|SAXParser` | Full containing function |
| Eval / code exec | `eval(\|new Function(\|vm\.runInContext\|compile(` | Full containing function |
| Queue dispatch | `addJob\|dispatch(\|publish(\|enqueue\|\.add(` | Full containing function |

**Priority**: Read sink matches in order of severity (RCE sinks first, then SQLi, SSRF, etc.).

---

### RAG Step 5 — Follow-the-Symbol (Targeted call chain tracing)

Once you have a suspicious endpoint + handler, trace the data flow using symbol search — do NOT read full files:

```
1. Grep for the handler function definition → read it
2. Identify the called functions that touch the input parameter
3. Grep for each called function's definition → read it
4. Repeat until you reach a sink or a sanitizer
5. Stop reading files that are not in the call chain
```

**Example trace**:
```
POST /api/search → handler: searchItems
  → grep "function searchItems\|searchItems =" → read that function
  → calls: buildSearchQuery(req.body.query)
  → grep "function buildSearchQuery\|buildSearchQuery =" → read it
  → uses: db.execute(`SELECT * WHERE name ILIKE '${query}'`)
  → STOP — raw interpolation into SQL — document finding
```

**Rule**: If a called function is in a vendor/node_modules directory — do not follow it. Use npm audit or known CVE databases instead.

---

### RAG Step 6 — Infrastructure Fast Scan (Always read these, they're small)

Regardless of repo size, always fully read these files — they are almost always small and contain high-severity findings:

```
docker-compose.yml / docker-compose.*.yml
Dockerfile
.env  /  .env.example  /  .env.production
kubernetes/*.yaml  /  k8s/**/*.yaml
terraform/**/*.tf
.github/workflows/*.yml
hasura/metadata/tables.yaml (or equivalent)
```

These take minimal context and frequently contain Critical findings (exposed ports, missing auth, secrets in env, overly permissive DB roles).

---

### RAG Step 7 — Archetype Batch Scan (Run all Phase 9 grep commands upfront)

Before deep per-file analysis, run all Phase 9 archetype grep patterns as a batch. For each match, note the file and line — read context only if the pattern looks exploitable:

**Batch scan order** (highest-severity archetypes first):

| Priority | Archetype | Quick Grep |
|----------|-----------|-----------|
| 1 | A15 Unauthenticated admin dashboard | `bull-board\|AdminJS\|swagger-ui\|pgadmin\|flower` |
| 2 | A16 Exposed Docker ports | Open `docker-compose.yml` → scan `ports:` sections for `0.0.0.0` bindings |
| 3 | A21 Crypto key gen without auth | `getSpendingKey\|generateKey\|getPrivateKey\|createKey` |
| 4 | A5 Unauthenticated queue dispatch | `addJob\|dispatch\|enqueue` → cross-ref with auth map from RAG Step 3 |
| 5 | A28 Webhook signature bypass | `webhook.*signature\|verifyWebhook\|x-hub-signature` |
| 6 | A26 CORS reflection | `allowedOrigins\|cors(` → check if origin header is echoed |
| 7 | A29 JWT kid/jku injection | `kid\b.*sql\|kid\b.*path\|jku\|x5u` in JWT verification code |
| 8 | A25 Mass assignment | `\.create(req\.\|assign.*body\|merge.*req` |
| 9 | A4 Dead security code | `rateLimit\|csrf\|authenticate` declared but never used in routes |
| 10 | A18 Destructive env var | `TRUNCATE\|DROP\|RESET\|WIPE\|DESTROY` in startup code |
| 11 | A33 File-identifier path traversal | `filepath\.Join\|path\.join\|GenerateFilePath\|BuildEFSPath` → check if arguments include `fileId\|fileName\|templateId\|sourceFile\|destFile` from user input without `filepath.Base` |
| 12 | A35 Cross-tenant IDOR | `GetBy.*ID\|FindByID\|GetFlowByID\|fetchById` → check for missing org/workspace ownership assertion after retrieval |
| 13 | A36 Auth middleware order bug | Read main router file → find routes registered before `app.Use\|api.Use\|router.Use` auth middleware — especially `hooks\|callback\|webhook` paths |
| 14 | A34 Arbitrary file deletion | `os\.Remove\|fs\.rm\|rimraf\|unlink` → check if path argument comes from stored user-supplied filename |

Each scan is seconds. Any hit that survives the auth map cross-reference becomes a high-priority taint trace in Phase 3.

---

### RAG Reading Budget

Apply a reading budget to prevent context overflow:

| File Type | Read Strategy |
|-----------|--------------|
| Route / controller files | **Full read** — these are the entry points |
| Middleware / guard / interceptor files | **Full read** — security controls |
| Config files (YAML, TOML, .env) | **Full read** — small, high-value |
| Infrastructure files (compose, Dockerfile, k8s) | **Full read** — always |
| Service / repository files | **Targeted read** — only functions in the call chain |
| Model / entity / schema files | **Grep for field names** — read field definitions only |
| Migration / SQL files | **Grep for table/column names** — read schema not data |
| Test files | **Skip** unless looking for hints about exploit conditions |
| Generated files | **Skip** |
| `node_modules` / `vendor` / `dist` / `build` | **Never read** — use dependency scanners instead |

**Hard limit**: If you have read more than 15 files and haven't found a Critical or High finding, stop full-file reading. Switch to grep-only mode and read only ±20 line windows around matches.

---

### RAG Phase Integration

Each phase has a preferred retrieval mode in large-codebase context:

| Phase | Preferred Retrieval |
|-------|-------------------|
| Phase 1 Threat Modeling | RAG Steps 1–3 + RAG Step 6 (infra). Output the priority matrix from grep results without reading implementations. |
| Phase 2 Data-Flow Mapping | RAG Step 5 (follow-the-symbol) for each high-priority entry point. Read only the call chain. |
| Phase 3 Taint Tracking | RAG Step 4 (sink-first) + RAG Step 5 (follow symbol back from sink to source). |
| Phase 4 Assumption Hunting | RAG Step 7 (archetype batch scan). Read context only for matches that survive the auth map check. |
| Phase 5 Compound Chains | No new reads — chain from findings already in context. |
| Phase 6 PoC Engineering | Read only the specific function(s) needed to write the PoC. |
| Phase 7 Scoring | No reads — score from data already collected. |
| Phase 8 Iterative Deepening | Re-run RAG Steps 4 and 7 for any newly identified sink categories or archetypes not yet checked. |

---

## Phase 1 — Threat Modeling & Component Isolation

> **Large repo?** Run RAG Steps 1–3 + RAG Step 6 above before reading any implementation file. Build the priority matrix from grep output alone, then read implementations only for top-priority entries.

Divide the target into functional components. For each:

### 1A. Map All Sources (Entry Points) — Extended Taxonomy

Enumerate every point where data enters the system. **Do NOT limit to direct user input** — trace data from all origins:

| Category | What to Search For | Why It Matters |
|----------|-------------------|----------------|
| **HTTP Request Structure** | Path params, query strings, JSON/form body, headers (`X-Forwarded-For`, `Host`, `Referer`, `Origin`, `Authorization`), cookies, multipart uploads, content-type negotiation | The request itself is the attack surface — not just the "user input" field |
| **URL Routing & Path Handling** | Route parameters, wildcard routes, path normalization, URL decoding steps, redirect targets, `req.url` / `req.path` / `req.originalUrl` differences, proxy-forwarded paths | Routing logic often trusts path components implicitly; double-encoding and path traversal bypass route guards |
| **Search & Filter Parameters** | `query`, `search`, `filter`, `orderBy`, `sortBy`, `cursor`, `after`, `before`, `offset`, `limit` — any parameter that influences SQL/ORM query construction or ordering | These parameters do NOT get validated as "user input" by most frameworks — they flow directly into query builders, ORDER BY clauses, and WHERE conditions |
| **Cursor/Pagination Tokens** | Base64-decoded cursors, JWT-like pagination tokens, opaque IDs decoded server-side | Attacker controls the cursor content; if decoded and used in queries without validation, it's a direct injection vector |
| **GraphQL Operations** | Query arguments, mutation inputs, subscription filters, nested resolver arguments, variable injection, query depth/complexity — run introspection (`{__schema{types{name}}}`) to map full schema | GraphQL exposes the entire API surface — every argument on every field is a potential source |
| **OAuth / SSO** | Authorization codes, `state` parameters, `redirect_uri` values, PKCE `code_challenge`, token exchange responses, SAML assertions, `id_token` claims, `nonce` values | OAuth flows have numerous client-controllable parameters; state tampering, redirect_uri manipulation, and nonce omission are classic account takeover vectors |
| **Blockchain/Chain Data** | On-chain events, extrinsic arguments, pallet call data, decoded SCALE types, block headers, transaction metadata | Chain data is often trusted as "blockchain-validated" but the indexer must handle malformed or adversarial on-chain data |
| **Environment & Config** | `process.env`, `.env` files, config files (YAML/JSON/TOML), command-line arguments, feature flags | Config values flow into security-critical operations (DB URLs, API keys, CORS origins) |
| **Inter-Process / Queue** | Message queue payloads (BullMQ, RabbitMQ, SQS), WebSocket messages, IPC, gRPC/protobuf deserialization, SNS/SQS notifications | Queue payloads inherit trust from the producer — if the producer is compromised or data is crafted, the consumer inherits the vulnerability |
| **Database Re-read** | Values previously stored in DB, cache entries (Redis, node-cache), session stores | Second-order injection: attacker stores payload in DB, different code path reads and uses it unsafely |
| **External Fetches** | HTTP responses from third-party APIs, webhook payloads, OAuth callback parameters, metadata fetched from external URLs (IPFS, Arweave, HTTP URIs) | External data is attacker-controlled if the attacker controls the external service or can MITM the connection |
| **File System** | Uploaded files, file paths constructed from user input, file contents parsed as config/data, ZIP archives (zip-slip), XML files (DOCX, SVG, XLSX) parsed server-side | File content is rarely validated beyond extension checks; XML files carry XXE risk |
| **File Identifiers as Hidden Paths** | Fields named `fileId`, `fileName`, `templateId`, `sourceFileName`, `destFileName`, `file_id`, `attachmentId` that are passed to path construction helpers (`GenerateFilePath`, `BuildEFSPath`, `filepath.Join`, `path.join`) — developers treat these as opaque IDs and skip path sanitization, but the helpers join them directly into filesystem paths | These are a distinct source category from "uploaded files" — they appear in node settings, API request bodies, and job/template configs; in Go `filepath.Join(base, "/etc/passwd")` returns `/etc/passwd` regardless of base |
| **Deployment / Infrastructure** | `docker-compose.yml`, `Dockerfile`, Kubernetes manifests, Terraform files, CI/CD pipelines (`.github/workflows`, `.gitlab-ci.yml`), build args, mounted volumes, exposed ports, health check endpoints | Deploy configs define the REAL security boundary — exposed ports, missing auth on services, secrets in build args, and `.env` files mounted into containers are all attack surface |
| **Admin Dashboards & Debug Endpoints** | Bull Board, pgAdmin, Hasura Console, Swagger/OpenAPI UI, Flower, Redis Commander, `/debug`, `/metrics`, `/health`, Prometheus endpoints | Admin UIs and debug routes are often deployed without auth middleware — each is a potential Critical finding |
| **Cross-Platform Sources** | Mobile: deep links, intent extras, `postMessage`, clipboard data. Desktop: IPC channels, registry keys, command-line args. Smart contracts: calldata, storage slots, event logs. Firmware: serial/UART input, BLE characteristics, OTA update payloads | The skill is not web-only — trace data from whatever the platform's entry points are |

### 1B. Map All Sinks (Dangerous Operations)

Search for every place where data becomes dangerous:

| Sink Category | Patterns |
|---------------|----------|
| Code execution | `eval(`, `exec(`, `compile(`, `new Function(`, `vm.runInContext`, `__import__` |
| Shell execution | `os.system`, `subprocess`, `child_process.exec`, `Popen`, backtick operators |
| Deserialization | `pickle.loads`, `yaml.load(` (unsafe loader), `JSON.parse` (prototype pollution), `jsonpickle`, Java `ObjectInputStream`, SCALE codec decode |
| XXE | `etree.parse`, `lxml.etree`, `DOMParser`, `DocumentBuilder`, `SAXParser`, any library parsing user-supplied XML (DOCX, SVG, XLSX) — check if external entity resolution is disabled |
| SQL / Query Builder | `.execute(` with string interpolation, raw query builders, ORM `.raw()`, `manager.query()` with template literals, TypeORM `createQueryBuilder` with `.where()` using string interpolation, parameterized queries with user-controlled column/table names |
| Mass assignment | `.create(req.body)`, `Object.assign(model, userInput)`, Mongoose `.set(body)`, TypeORM `merge(entity, dto)` without an explicit allowlist — attacker controls arbitrary fields including `role`, `isAdmin`, `price`, `ownerId` |
| Prototype pollution | `_.merge()`, `deepmerge()`, `Object.assign()` on nested objects, recursive copy functions — if `__proto__` key reaches merge, attacker modifies `Object.prototype` → auth bypass or RCE via template gadget |
| File system | `open(` with user path, `path.join(` + user input, `fs.readFile/writeFile`, `zipfile.extractall` (zip-slip) |
| Template rendering | `render_template_string(`, Jinja2 `Environment(autoescape=False)`, server-side template injection, JSX `dangerouslySetInnerHTML` |
| Redirects | `redirect(user_input)`, `Location:` header with user-controlled value, `window.location` assignment |
| Cryptography | `hashlib.md5/sha1` for passwords, `Math.random()` (not `crypto.randomBytes`), `AES-ECB`, static IVs, `signatureVerify` without replay protection |
| Memory / C-ext | `ctypes`, `cffi`, buffer operations without bounds checking, BigInt overflow |
| External requests (SSRF) | `fetch(`, `axios(`, `http.request(` with user-controlled URL, metadata endpoint access (`169.254.169.254`) |
| Queue dispatch | Job dispatching with user-controlled IDs without rate limiting, job replay/poison pill attacks |

### 1C. Map Security Boundaries

For each route/function, identify:
- **Auth gate**: `auth='none'` / `auth='public'` / `auth='user'` / `auth='admin'` or equivalent
- **CSRF protection**: csrf token present / `csrf=False` / SameSite cookies
- **Authorization checks**: ACL checks, ownership validation (can user A access user B's resource?)
- **Rate limiting**: Is the endpoint rate-limited? Can an attacker flood it?
- **Input validation layer**: type-graphql validators, class-validator decorators, Joi/Zod schemas, regex guards
- **Query complexity limits**: For GraphQL — is there depth limiting, cost analysis, or complexity throttling?
- **CORS configuration**: Is `Access-Control-Allow-Origin` reflected from the `Origin` header? Does `null` origin work? Are credentials allowed (`Access-Control-Allow-Credentials: true`) with non-allowlisted origins? Reflected origin + credentials = account takeover via cross-origin request.
- **HTTP method controls**: Does the app honor `X-HTTP-Method-Override` or `_method` parameters? Non-standard HTTP verbs or override headers can bypass method-specific auth guards and CSRF checks.

### 1D. Priority Matrix

Rank attack surface: **(unauthenticated surface) × (sink severity) × (data flow complexity)**

Output a ranked table:

| Priority | Component | File:Line | Auth | Key Sources | Key Sinks | Data Path Complexity | Why High Priority |
|----------|-----------|-----------|------|-------------|-----------|---------------------|-------------------|

**Start with unauthenticated routes that reach critical sinks through complex data paths. These are your zero-day candidates.**

---

## Phase 2 — Deep Data-Flow Mapping (How Data Actually Moves)

> **Phase 2 vs Phase 3**: Phase 2 maps *how* data transforms between functions — the landscape. Phase 3 formally documents source→sink chains — the paths. Do Phase 2 first to understand the transformation landscape before tracing specific chains in Phase 3.
>
> **Large repo?** Use RAG Step 5 (follow-the-symbol) for each high-priority endpoint from Phase 1. Do NOT read entire service or repository files — grep for specific function names and read only the matching definitions.

### 2A. Function-Level Data Transformation Tracking

**Do NOT assume data comes from "user input" directly.** Trace how data is actually constructed at each function boundary:

For every function that handles data:
1. **Where does each parameter ACTUALLY come from?** Trace backwards:
   - Is it from `req.body.field` directly? Or is it extracted from a decoded cursor? Or reconstructed from a database lookup?
   - Is it from a GraphQL argument that was validated by type-graphql? Or does it bypass validation?
   - Is it from a blockchain event that was decoded from SCALE format? What are the type constraints?

2. **How does the HTTP request structure influence execution?**
   - Does the URL path determine which code branch executes? (routing-based dispatch)
   - Do query parameters change the SQL ORDER BY / WHERE clause? (query parameter injection)
   - Does the `Content-Type` header change parsing behavior? (content-type confusion)
   - Do custom headers (`X-Forwarded-For`, `X-Real-IP`) flow into trusted operations?

3. **How do search/filter parameters flow into queries?**
   Track the exact transformation chain:
   ```
   GraphQL arg `query: string`
     → validated: [YES/NO, how?]
     → passed to: [function name]
     → used in: SQL ILIKE clause / ORM .where() / raw query template
     → sanitized: [YES/NO — is it parameterized? Or string-interpolated?]
   ```

4. **How does cursor/pagination data flow?**
   ```
   Base64 cursor string
     → decodeCursor() parses JSON
     → extracts: { id, orderValue }
     → id used in: WHERE clause with parameterized query? Or string interpolation?
     → orderValue used in: comparison operator? Column name? ORDER BY?
   ```

### 2B. Implicit Trust Boundary Analysis

Identify where the code implicitly trusts data that it shouldn't:

| Pattern | Example | Risk |
|---------|---------|------|
| "It came from our database, so it's safe" | DB value used in raw SQL without parameterization | Second-order SQLi |
| "Blockchain data is validated by consensus" | On-chain event args used directly in SQL/rendering | Malicious contract can emit crafted events |
| "Internal queue messages are trusted" | BullMQ job payload used without validation | Queue poisoning if Redis is accessible |
| "The ORM handles escaping" | TypeORM `.where()` with string interpolation for column names | Column injection |
| "Enum validates the input" | TypeScript enum used in switch but SQL uses the raw string value | Enum bypass if GraphQL accepts arbitrary strings |
| "Validators check the input" | class-validator on one field, but other fields unchecked | Selective validation gaps |
| "It passed OAuth, so the user data is safe" | JWT claims used in queries or templates without re-validation | JWT forgery, claim injection |

---

## Phase 3 — Source-to-Sink Taint Tracking

> **Large repo?** Use RAG Step 4 (sink-first scanning) to locate sinks via grep. Then use RAG Step 5 (follow-the-symbol) to trace backwards from each sink to its source. Read only the files in the taint path — not surrounding modules.

For each high-priority component, trace the complete data flow. Assume all data is malicious until mathematically proven otherwise.

### 3A. Full Taint Chain Documentation

For every path from source to sink:

```
SOURCE:  [HTTP method / GraphQL query / Chain event / Queue job]
         auth='[level]'  csrf=[on/off]  rate_limit=[on/off]
         param: [parameter_name] = <ATTACKER CONTROLLED>
         origin: [direct input / decoded cursor / DB re-read / chain event / queue payload / OAuth claim]
           ↓
  [function1(param)]
  transforms: [original type] → [new type/value]
  validation: [class-validator / regex / type check / NONE]
           ↓
  [sanitizer_check(var)]  ← BYPASS ANALYSIS (see 3B)
           ↓
  [function2(var)]
  transforms: ...
  trust_boundary_crossed: [YES: queue → worker / NO]
           ↓
SINK: [dangerous_operation(var)]  → IMPACT: [what attacker achieves]

Verdict: EXPLOITABLE / CONDITIONAL [on: X] / BLOCKED [by: exact mechanism]
```

### 3B. Sanitizer Bypass Analysis — CRITICAL STEP

**Do NOT accept a sanitizer as blocking without attempting to bypass it.**

For every sanitizer in the chain, ask:

| Sanitizer Type | Bypass Techniques to Evaluate |
|----------------|-------------------------------|
| Regex/pattern match | Unicode normalization (`Ａ` vs `A`), null bytes (`\x00`), newline injection (`\r\n`), case variants, double encoding (`%252e`), overlong UTF-8, ReDoS with catastrophic backtracking |
| File extension check | Double extension (`shell.php.jpg`), null byte termination (`shell.php\x00.jpg`), MIME sniffing vs extension mismatch, case (`Shell.PHP`), trailing dots/spaces on Windows |
| Path traversal filter | `../`, `%2e%2e%2f`, `%2e%2e/`, `..%2f`, absolute path (`/etc/passwd`), Windows `..\\`, UNC paths, symlink race — **in Go: `filepath.Join("/base", "/etc/passwd")` returns `/etc/passwd`** (absolute path argument completely overrides the base); fix requires `filepath.Base(input)` BEFORE joining; also test inputs that are MongoDB ObjectIDs or UUIDs containing `/` injected characters |
| Allowlist filter | Substring match vs full-string match? Can attacker prepend/append allowed value? Is the check case-sensitive? |
| Length check | Off-by-one, Unicode code points vs bytes, truncation after validation but before use |
| Signature/HMAC check | Empty secret key behavior, timing attack, algorithm confusion (RS256→HS256), missing `exp`/`nbf` validation |
| Type check | `typeof` vs `instanceof`? Can attacker pass a subclass/prototype? Does NaN pass numeric checks? |
| Enum validation | Does the GraphQL layer enforce enums strictly? Or does the resolver receive raw strings? Is the enum value used directly in SQL? |
| class-validator | Is `@Validate()` actually called? Does `whitelist: true` strip extra properties? Are nested objects validated? |
| Parameterized query | Are column names / table names parameterized? (They can't be in most ORMs — only values can be parameterized) |
| Prototype pollution filter | Filter for `__proto__`, `constructor`, `prototype` — test URL-encoded variants (`%5F%5Fproto%5F%5F`), unicode variants, and nested-object bypass (`{"a":{"__proto__":{"isAdmin":true}}}`) |

**Output per sanitizer**: `Bypassable: YES/NO/PARTIAL` + exact bypass vector if yes.

### 3C. Type Confusion Analysis

At every API boundary, test what happens with unexpected types:
- Integer field → huge JSON array, float, string, negative, zero, MAX_SAFE_INTEGER+1, BigInt overflow
- String field → JSON object `{}`, array `[]`, extremely long string (100KB+)
- Boolean field → `0`, `"false"`, `null`, `[]`, empty string
- Expected array → single item (non-array), empty array, array with 10,000 items
- BigInt/numeric string → NaN, Infinity, `-0`, scientific notation (`1e308`)
- Hex string / address → short string, missing `0x` prefix, wrong length, non-hex chars

Ask: Does the parser crash? Does it bypass validation? Does it cause a type error that leaks internal state?

---

## Phase 4 — Assumption Failure Hunting (Zero-Day Goldmine)

> **Large repo?** Use RAG Step 7 (archetype batch scan) to run all Phase 9 grep patterns first. Read file context (±20 lines) only for matches that survive the auth map cross-reference from RAG Step 3.

**Standard scanners find syntax errors. Zero-days are logic errors. Attack the developer's assumptions.**

### 4A. Race Conditions (TOCTOU)

Search for the pattern: **check → gap → use**

```
if has_permission(user, resource):   # CHECK
    # ...any code here is a gap...   # GAP
    perform_action(resource)          # USE
```

Identify:
1. **Multi-step workflows** where state is checked at step 1 but used at step 3
2. **Non-atomic read-modify-write** on shared resources (counters, balances, quota limits)
3. **Double-spend patterns**: can a resource (coupon, token, listing) be consumed twice by sending concurrent requests?
4. **File-based TOCTOU**: `fs.existsSync()` → `fs.readFileSync()` with symlink substitution
5. **Blockchain indexer race**: can a chain reorg cause double-processing of events? Are event deduplication checks atomic?
6. **Queue job race**: can the same job ID be dispatched twice before the first completes?

For each candidate: estimate the exploitable window size.

### 4B. Business Logic Flaws

Understand the *purpose* of the app, then ask what happens when that purpose is abused:

1. **State machine abuse**: Can a cancelled listing be filled? Can a finalized auction be bid on? Map all valid state transitions and test invalid ones.
2. **Price/quantity manipulation**: What if amount is negative? Zero? MAX_SAFE_INTEGER? Fractional for an integer-only field?
3. **Tenant/IDOR isolation**: Can user A access user B's resources by guessing/enumerating IDs? Are collection IDs / token IDs sequential and predictable? Are UUIDs v1 (timestamp-based, predictable)? Are "hash-based" IDs actually `MD5(user_id)`?
4. **Privilege escalation via parameter**: Is there a `role=`, `admin=`, `type=` field in user-controlled input that gets trusted?
5. **Workflow bypass**: Can step 3 of a 5-step process be accessed directly?
6. **Pagination abuse**: Can negative offset/limit cause data leakage? Can extremely large `first` values cause DoS?
7. **Search abuse**: Can the `query` parameter extract data through timing or error differences? Can wildcards (`%`, `_`) in ILIKE leak data?
8. **HTTP method override**: Does the app honor `X-HTTP-Method-Override` or `_method` query/body parameter? A GET can become a DELETE, bypassing method-specific auth guards and CSRF protection.
9. **Rate limit IP bypass**: Does rate limiting use `X-Forwarded-For` or `X-Real-IP`? If the proxy trusts these headers from clients, an attacker can rotate IPs by changing the header value and bypass per-IP rate limits indefinitely.
10. **API version downgrade**: Does `/api/v1/endpoint` lack security controls added in `/api/v2/endpoint`? Old versions are often not removed. Test all discovered versions for auth, rate limiting, and input validation gaps.

### 4C. Cryptographic Mishandling

Do not just check algorithm names — check implementations:

| Pattern | What to Look For |
|---------|-----------------|
| IV/Nonce reuse | Hardcoded, zero, or derived from non-random source? |
| ECB mode | AES-ECB leaks patterns |
| Weak KDF | `hashlib.sha256(password)` — no salt, no iterations |
| Predictable randomness | `Math.random()` for security tokens; must use `crypto.randomBytes` |
| JWT confusion | `alg: none` accepted? RS256 key accepted as HS256 secret? Missing `exp` / `iss` / `aud` validation? `kid` header used in DB lookup or file path without sanitization (SQLi / path traversal via JWT header)? `jku` / `x5u` header pointing to attacker-controlled key server? |
| Timing oracle | String comparison with `===` on secret values — use `timingSafeEqual` |
| Padding oracle | CBC mode decryption with error messages that differ between bad padding vs bad MAC/plaintext — attacker can decrypt or forge ciphertext byte-by-byte |
| Signature replay | Is there a nonce/timestamp preventing replay of signed messages? |
| Key exposure | Private keys, API secrets, tokens in source, logs, error messages |
| Hash collision | Are xxhash or non-cryptographic hashes used for security-critical deduplication? |

### 4D. Second-Order & Stored Injection

Track data that is **stored first, then used later** in a dangerous operation:

1. Input → stored in DB → later used in raw SQL query without parameterization (stored SQLi)
2. Input → stored as metadata → later rendered without encoding (stored XSS via GraphQL response)
3. Input → stored as config/attribute → later interpolated into system command
4. Input → cached → served to other users without per-user sanitization
5. Blockchain event data → stored in indexer DB → later used in GraphQL resolver's raw SQL
6. External metadata URI → fetched and stored → content used unsafely (SSRF via metadata fetch)

### 4E. Denial of Service (Computational & Resource)

1. **GraphQL complexity abuse**: Deeply nested queries, aliased field explosion, batch queries
2. **Regex DoS (ReDoS)**: Input that causes catastrophic backtracking in regex patterns
3. **Large payload processing**: Unbounded array/object sizes in request bodies
4. **Database query amplification**: Single API call that triggers N+1 queries or full table scans
5. **Queue flooding**: Can an attacker dispatch unlimited jobs to BullMQ queues?
6. **Memory exhaustion**: Operations that accumulate data without bounds (e.g., `Map` grows without limit)

### 4F. Dependency & Supply Chain

1. Check `package.json` / `requirements.txt` for known CVE'd packages
2. Look for unpinned dependency versions
3. Check if any dependency is loaded from user-controlled or remotely-fetched source
4. Verify lockfile integrity

### 4G. Prototype Pollution

Prototype pollution allows an attacker to inject properties into `Object.prototype`, which then appear on every object in the application — bypassing auth checks or reaching RCE via template gadgets.

1. **Sources**: `req.query`, `req.body`, URL parameters, JSON body, query string parsing libraries
2. **Vulnerable operations**: `_.merge(obj, userInput)`, `deepmerge(a, b)`, `Object.assign({}, parsed)`, recursive copy/extend functions
3. **Sink paths**:
   - Polluted `isAdmin`, `role`, `authenticated` on `Object.prototype` → auth bypass
   - Polluted `__proto__.outputFunctionName` in Pug/Jade → RCE
   - Polluted `__proto__.escapeFunction` in lodash templates → RCE
4. **Detection**: Search for `merge(`, `extend(`, `deepCopy(`, `assign(` — check if user input reaches nested key assignment without `Object.create(null)` protection
5. **Test payloads**:
   ```json
   {"__proto__": {"isAdmin": true}}
   {"constructor": {"prototype": {"isAdmin": true}}}
   ```
   Or via query string: `?__proto__[isAdmin]=true`
6. **RCE gadget via Pug**: If `__proto__.outputFunctionName` can be set to an expression like `x;process.mainModule.require('child_process').execSync('id')//`, any Pug render becomes RCE.

---

## Phase 5 — Compound Vulnerability Chaining

**Two medium-severity bugs that chain together = critical finding.**

For every pair of findings, ask:
1. Does finding A grant an attacker capability X?
2. Does finding B require capability X as a precondition?
3. If yes: document the chain as a single critical finding.

Common compound patterns:
- **SSRF + IMDSv1** → cloud credential theft → account takeover
- **GraphQL query injection + stored data** → extract all user data
- **Cursor injection + SQL column reference** → arbitrary data extraction
- **Queue poisoning + job handler trust** → code execution in worker
- **Metadata URI SSRF + internal service** → access internal APIs
- **Open redirect + OAuth** → token hijack → account takeover
- **Rate limit bypass + brute force** → credential stuffing
- **Error message info leak + SQL injection** → database structure discovery → targeted extraction
- **CORS origin reflection + stored XSS** → attacker hosts malicious page that reads victim's session cookies or CSRF tokens cross-origin, exfiltrates them
- **Prototype pollution + eval/template sink** → pollution sets gadget property (`outputFunctionName`) → arbitrary code execution via template render
- **Mass assignment + privilege check** → attacker sets `role=admin` or `isAdmin=true` in create/update payload → all subsequent auth checks pass
- **API version downgrade + missing auth** → v1 endpoint has no auth that v2 added → authenticated data exposed without credentials
- **File-identifier path traversal + file cleanup** → attacker supplies crafted fileName (e.g., `../../secrets.yaml`) during node creation → cleanup later calls `os.Remove` on it → arbitrary file deletion of application config or secrets
- **Missing org check + sub-flow / resource execution** → cross-tenant resource ID accepted → attacker executes another tenant's flow or reads their assets using their own credentials
- **Auth middleware registration order bug + callback endpoint** → callback/webhook/hook route registered before JWT middleware → unauthenticated attacker can trigger privileged actions (e.g., subscribe arbitrary users to channels, trigger flow execution)

---

## Phase 6 — PoC Engineering & Verification Strategy

For every non-blocked finding, produce:

### 6A. Minimum Reproducible PoC

Exact curl command, Python snippet, or GraphQL query:

```graphql
# GraphQL PoC example
query ExploitExample {
  targetResolver(
    maliciousParam: "PAYLOAD_HERE"
  ) {
    sensitiveField
  }
}
```

```bash
curl -X POST https://TARGET/graphql \
     -H "Content-Type: application/json" \
     -d '{"query": "[exact exploit query]", "variables": {}}'
```

### 6B. PoC Search Methodology — How to Find the Right PoC

For each vulnerability class, follow this search strategy to build the PoC:

| Vulnerability Class | PoC Search Strategy |
|---------------------|--------------------|
| **SQL Injection** | 1. Identify the exact SQL context (WHERE / ORDER BY / LIMIT / column name) → 2. Determine DB engine (PostgreSQL CAST, MySQL GROUP BY) → 3. Test with time-based blind payloads first (`pg_sleep(5)`) → 4. Escalate to UNION SELECT if error-based confirms → 5. Extract version, then table names, then data |
| **GraphQL Abuse** | 1. Introspection query to map full schema → 2. Test each resolver argument for type confusion → 3. Test query complexity (nested fragments, aliases) → 4. Test batch queries for rate limit bypass → 5. Test mutations for authorization bypass |
| **SSRF** | 1. Test with external canary (Burp Collaborator / Interactsh) → 2. Test `http://169.254.169.254/latest/meta-data/` → 3. Test `file:///etc/passwd` → 4. Test DNS rebinding → 5. Test redirect-based filter bypass |
| **Race Condition** | 1. Identify the TOCTOU window → 2. Write concurrent request script (asyncio/threading) → 3. Send 50+ parallel requests → 4. Check for double-spend or state corruption → 5. Measure success rate over 100 attempts |
| **Auth Bypass** | 1. Test unauthenticated access → 2. Test with expired/malformed tokens → 3. Test horizontal access (user A → user B data) → 4. Test vertical access (user → admin) → 5. Test parameter manipulation (`role=admin`) |
| **DoS** | 1. Craft minimal payload that maximizes server computation → 2. Measure response time with baseline vs attack → 3. Demonstrate >10x response time increase → 4. Show resource exhaustion (CPU %, memory) if possible |
| **Cursor/Pagination Injection** | 1. Decode the cursor format (base64 → JSON) → 2. Modify `id` and `orderValue` fields → 3. Test if modified values reach SQL without parameterization → 4. Test column name injection via orderValue → 5. Test for data extraction via error-based or boolean-based responses |
| **Prototype Pollution** | 1. Test `?__proto__[x]=polluted` on all endpoints → 2. Check if `{}["x"]` === "polluted" in response → 3. Find gadget in app (Pug, lodash template, JSON serializer) → 4. Craft pollution payload targeting the gadget property → 5. Escalate to RCE if template gadget reachable |
| **XXE** | 1. Find XML-consuming endpoint (file upload, SOAP, config import) → 2. Submit `<!DOCTYPE x [<!ENTITY xx SYSTEM "file:///etc/passwd">]><x>&xx;</x>` → 3. If response echoes file: confirmed in-band → 4. If blind: use OOB via parameter entity with attacker-controlled DTD → 5. Test `SYSTEM "http://attacker.com/"` for SSRF |
| **Mass Assignment** | 1. Get normal create/update request body → 2. Add sensitive fields (`role`, `isAdmin`, `price`, `ownerId`, `verified`) → 3. Submit and check GET response to see if fields were persisted → 4. Verify impact: re-login or check permissions with the modified account |

### 6C. Sanitizer-Targeted Payload Set

5–10 payloads specifically targeting the sanitizers in the chain:

```
Payload 1: [base payload]                  — tests basic case
Payload 2: [encoded variant]               — tests URL/HTML encoding bypass
Payload 3: [unicode variant]               — tests normalization bypass
Payload 4: [type confusion variant]        — tests parser confusion
Payload 5: [boundary/edge case]            — tests off-by-one or length limit
Payload 6: [second-order stored variant]   — tests when payload is stored then retrieved
Payload 7: [chain context variant]         — tests when combined with another finding
```

### 6D. Exploit Simulation

Before claiming exploitability, simulate the full exploit chain mentally:

> "If I trigger [overflow/injection/TOCTOU], can I achieve [RCE/data exfil/account takeover], or does the application safely crash/restart/log-and-continue?"

Answer:
- What is the attacker's actual capability after triggering this?
- What preconditions are needed (auth level, config, timing window)?
- What is the reliability of exploitation (one-shot / requires retries / probabilistic)?
- What would the PoC output look like on a live instance?

---

## Phase 7 — Confidence Scoring & Blast-Radius Triage

### 7A. Confidence Score (0–100)

For every finding, assign a **Confidence Score** from 0 to 100 representing the probability that this is a confirmed, exploitable, bounty-worthy vulnerability:

| Score Range | Meaning | Criteria |
|------------|---------|----------|
| **90–100** | **Confirmed Exploitable** | Full taint chain verified, no blocking sanitizer, PoC demonstrated, impact is clear (RCE/data exfil/account takeover). Ready to submit. |
| **75–89** | **High Confidence** | Taint chain complete, sanitizer bypass identified but not fully tested live, impact assessment solid. Needs live verification only. |
| **50–74** | **Medium Confidence** | Taint path exists, sanitizer status unclear (may be bypassable), impact depends on configuration or environment. Worth investigating further. |
| **25–49** | **Low Confidence** | Theoretical vulnerability, sanitizer may block, limited impact, or requires unlikely preconditions. Investigate only if time permits. |
| **0–24** | **Informational** | Code smell, best practice violation, or hardening opportunity. Not exploitable in current context but worth noting. |

**Scoring Formula:**

```
Confidence = (Taint_Completeness × 0.30)
           + (Sanitizer_Bypass_Proof × 0.25)
           + (Impact_Severity × 0.20)
           + (Precondition_Feasibility × 0.15)
           + (PoC_Reproducibility × 0.10)
```

Where each sub-score is 0–100:
- **Taint_Completeness**: Is every step from source to sink documented? (100 = full chain, 0 = theoretical)
- **Sanitizer_Bypass_Proof**: Are all sanitizers bypassed with proof? (100 = all bypassed with payload, 50 = some bypassed, 0 = no bypass found)
- **Impact_Severity**: RCE=100, Data Exfil=90, Account Takeover=85, PrivEsc=80, DoS=60, Info Disclosure=40, Code Smell=10
- **Precondition_Feasibility**: No auth needed=100, User auth=70, Admin auth=30, Requires collab with victim=20, Requires specific config=40
- **PoC_Reproducibility**: Deterministic one-shot=100, Requires retries=70, Timing-dependent=40, Theoretical only=10

### 7B. Finding Verdict Card

For every finding, produce:

```markdown
## FINDING [N] — [Short Title]

### Confidence Score: [0-100] / 100
| Sub-Score | Value | Justification |
|-----------|-------|---------------|
| Taint Completeness | /100 | [brief reason] |
| Sanitizer Bypass Proof | /100 | [brief reason] |
| Impact Severity | /100 | [brief reason] |
| Precondition Feasibility | /100 | [brief reason] |
| PoC Reproducibility | /100 | [brief reason] |

### Classification
- **Severity**: Critical / High / Medium / Low / Informational
- **Category**: RCE / PrivEsc / Data Exfiltration / DoS / Auth Bypass / IDOR / Injection / Logic Flaw / Crypto / Info Disclosure
- **Auth Required**: None / Public / Authenticated User / Admin
- **File**: path/to/file.ts:line_number
- **In-scope for bug bounty**: Yes / No / Depends on program

### Taint Chain (full path)
SOURCE → [transforms] → [sanitizers + bypass status] → SINK

### Data Source Origin
[Explain exactly WHERE the attacker-controlled data comes from — is it a direct GraphQL argument? A decoded cursor? A stored DB value? A chain event? An OAuth claim? Explain the full origin chain.]

### Why It's Real (not a false positive)
[Address every sanitizer in the chain explicitly. Confirm none block exploitation.
If conditional: state exact conditions required.]

### Sanitizer Bypass Proof
[If a sanitizer exists, show the exact bypass payload and why it works]

### PoC
```[language]
[minimum reproducing command/script]
```

### PoC Verification Steps
1. [Step to set up prerequisites]
2. [Step to send the exploit]
3. [Step to observe the impact]
4. [Expected output that confirms exploitation]

### Exploit Simulation
[Walk through what happens after the payload lands. What capability does the attacker gain?
Can they escalate further? What is the practical blast radius?]

### Conditions Required
- [ ] Auth level: [none/user/admin]
- [ ] Config state: [default/custom setting required]
- [ ] Timing: [race window required?]
- [ ] Environment: [cloud provider/OS specific?]
- [ ] Other preconditions: [list]

### Impact
[Concrete attacker outcome: what data/systems/accounts are compromised?]

### Compound Chain Potential
[Can this be chained with another finding? Which one and what is the combined impact?]

### Verdict
- **Exploitable**: Yes / No / Conditional on [X]
- **Confidence Score**: [0–100]
- **Reliability**: High (deterministic) / Medium (requires retries) / Low (timing-dependent)
- **CVSS estimate**: [score] ([vector string])
- **Bounty tier**: Critical ($$$) / High ($$) / Medium ($) / Out of scope
- **Next step to confirm on live instance**: [specific test]
```

---

## Phase 8 — Iterative Deepening Loop

**This phase is what separates surface-level scanning from deep adversarial research.**

After completing Phases 1–7, execute the improvement loop:

### 8A. Gap Analysis

Review all findings and ask:
1. **What attack vectors did I NOT explore?** List them explicitly.
2. **Which components got shallow coverage?** Identify files/functions that were noted but not deeply analyzed.
3. **Which source categories from Phase 1A did I not fully trace?** (e.g., "I checked GraphQL args but not decoded cursors" or "I checked HTTP params but not chain event data")
4. **What sanitizers did I accept as blocking without full bypass analysis?**
5. **Which Phase 9 archetypes did I not search for?** List the ones not yet checked.

### 8B. Pattern Expansion

For each finding discovered, ask:
1. **Does this pattern repeat elsewhere in the codebase?** Search for similar code constructs.
2. **Can I find a more impactful variant?** (e.g., if I found SQLi in a read-only context, is the same pattern used in a write context?)
3. **Can I find a lower-precondition variant?** (e.g., if the auth-required finding has an unauthenticated equivalent)

### 8C. Cross-Component Analysis

Look for vulnerabilities that span multiple components:
1. **GraphQL resolver → Queue worker**: Does data from a resolver reach a worker without re-validation?
2. **Chain event → DB → GraphQL response**: Does on-chain data flow through to user-facing output without sanitization?
3. **External metadata fetch → DB storage → Raw SQL**: Does metadata from IPFS/HTTP get stored and later used in raw queries?
4. **Config → Runtime behavior**: Do environment variables control security-critical branching?

### 8D. Iterate

Repeat Phases 2–7 for any newly discovered attack vectors. Each iteration should produce:
- New findings OR
- Increased confidence in existing findings OR
- Explicit documentation of why a vector is not exploitable

**Stop iterating when:**
- All high-priority components have been deeply analyzed
- All sanitizers have been challenged with bypass attempts
- All cross-component flows have been traced
- Confidence scores are stable (not increasing with more analysis)

### 8E. Methodology Improvement via Web Research (Skill Growth Stage)

> **Key Principle**: Web research is NOT for finding bugs in the current target. It is for **improving the patterns and checklists in each Phase** so the methodology catches more bugs on EVERY future run.

**After each audit pass**, search the web to improve the skill itself:

#### Step 1: Identify Phase Gaps

For each Phase (1–7), ask: "What patterns or checks am I missing?"
- Phase 1 Source Taxonomy — Are there source categories I haven't listed?
- Phase 2 Data Flow — Are there data transformation patterns I don't trace?
- Phase 3 Sanitizer Bypass — Are there bypass techniques not in my table?
- Phase 4 Assumption Hunting — Are there business logic flaw patterns I haven't considered?
- Phase 5 Compound Chains — Are there chain patterns not in my list?
- Phase 6 PoC Engineering — Are there PoC strategies per vulnerability class I'm missing?
- Phase 7 Scoring — Is my scoring formula missing relevant factors?

#### Step 2: Research to Fill Each Gap

Search the web with **phase-specific** queries — not target-specific:

| Phase | Research Query Template | What to Extract |
|-------|------------------------|------------------|
| **Phase 1** | `"OWASP input sources" OR "untrusted data entry points"` | New source categories for the Source Taxonomy table |
| **Phase 2** | `"[ORM/framework] security pitfalls data flow"` | New implicit trust boundary patterns for 2B table |
| **Phase 3** | `"[sanitizer type] bypass techniques [year]"` | New bypass techniques for 3B Sanitizer Bypass table |
| **Phase 4** | `"business logic vulnerability patterns" OR "race condition methodology"` | New assumption-failure patterns for 4A-4G checklists |
| **Phase 5** | `"vulnerability chaining examples" OR "compound exploit chains"` | New chain patterns for compound patterns list |
| **Phase 6** | `"[vuln class] proof of concept methodology"` | New PoC strategies for 6B table |
| **Phase 7** | `"vulnerability scoring methodology"` | Scoring formula improvements |

#### Step 3: Inject Patterns Back Into Phases

For each useful pattern found:
1. **Add it to the correct Phase's checklist/table** (not as a standalone finding)
2. **Make it generic** — remove target-specific details, keep the abstract pattern
3. **Add a detection strategy** — how should the auditor search for this in ANY codebase?

```
WRONG: "TypeORM SQL injection in [target] accounts.ts"
RIGHT: Add to Phase 3B table:
  | ORM query builder | .orderBy()/.groupBy()/.addSelect() may receive enum
  |                   | values that are raw SQL strings — column names can't
  |                   | be parameterized, so enums bypass protection. |
```

---

## Phase 9 — Vulnerability Archetype Library (Reusable Pattern Repository)

> **Purpose**: A growing library of reusable detection patterns — NOT findings from one specific audit. Each archetype works for ANY codebase.
>
> **When to use**: Consult this library from Phase 1 onwards — search for each archetype as you analyze the codebase. Do not wait until the end.

After each audit, extract any **new archetype** discovered and add it here. Each archetype must be:
1. **Abstract** — no target-specific file names or details
2. **Detectable** — includes grep/search commands that work on any codebase
3. **Phase-linked** — specifies which Phase(s) should check for it

### Archetype Library

| # | Archetype | Abstract Pattern | Detection Strategy | Phases |
|---|-----------|------------------|--------------------|--------|
| A1 | **Enum-to-SQL passthrough** | Enum values ARE raw SQL fragments passed to `.orderBy()` or interpolated into `.where()` | `grep -rn "orderBy\|groupBy\|addSelect"` → trace to enum definition → check if values contain SQL | 2, 3 |
| A2 | **Infrastructure metadata over-permission** | Config files grant `public`/`anonymous` roles unrestricted read access | Search for `hasura_metadata`, schema configs → check for `role: public`, `columns: *`, empty `filter` | 1, 4 |
| A3 | **Incomplete sanitizer** | Custom `safe*`/`sanitize*` only checks one vuln class (e.g., null bytes) but misses others (XSS, SQLi) | Read every `safe*/sanitize*/clean*/validate*` function → test with payloads from ALL vuln classes | 3 |
| A4 | **Dead security code** | Security features declared but never wired into request flow | `grep "rateLimit\|csrf\|authenticate"` → verify each is USED, not just defined | 4 |
| A5 | **Unauthenticated queue dispatch** | API endpoints push jobs to queues without auth or rate limiting | `grep "dispatch\|addJob\|publish\|enqueue"` → trace to API endpoint → check auth | 1, 4 |
| A6 | **SSRF via stored URIs** | External URLs in DB fetched server-side with bypassable SSRF protection | `grep "fetch\|axios\|http.request"` → check URL source → test DNS rebinding, IPv6, protocol bypass | 3, 5 |
| A7 | **Queue payload trust** | Workers use `job.data.*` without re-validation | Check every queue consumer: is `job.data` validated before DB queries, URL construction, file ops? | 2, 4 |
| A8 | **Decode function DoS** | Decoding functions (SS58, base58, base64, or any parse-at-boundary) throw on invalid input → uncaught DoS | `grep "decode\|fromBase58\|fromBase64\|JSON.parse"` → verify try/catch at API boundary | 4 |
| A9 | **ORM proxy public role** | DB proxy layers (Hasura, PostGraphile, Prisma) with anonymous/public SELECT * | Check all proxy config for role definitions → verify row-level filters are non-empty | 1, 4 |
| A10 | **Pagination unbounded** | No max on `limit`/`first`, no query cost analysis, cursor injection possible | Test `limit: 999999`, decode+modify cursors, check for alias multiplication | 4, 6 |
| A11 | **TOCTOU validation gap** | Security check → async gap → state use | Search for: check → `await` → use (balance, permission, file existence checks) | 4 |
| A12 | **Second-order stored injection** | Data stored safely → later used unsafely in raw SQL, templates, or commands | Trace every DB read → check if values reach raw queries, HTML output, or command construction | 3, 4 |
| A13 | **GraphQL complexity abuse** | No depth limit, no cost analysis, no batching limit | Check server config for `maxDepth`, `maxComplexity` → test nested queries + aliases | 4, 6 |
| A14 | **Signature replay** | Signature verification without nonce/timestamp/expiry | Check every `verify*` call → verify nonce or timestamp in signed payload | 4 |
| A15 | **Unauthenticated admin dashboard** | Admin UIs (Bull Board, Flower, pgAdmin, Redis Commander, Hasura Console) exposed without auth middleware | `grep -rn "bull-board\|AdminJS\|express-admin\|swagger-ui"` → check if auth middleware exists before the route + check Docker port mappings | 1, 4 |
| A16 | **Exposed services without auth in Docker/K8s** | `docker-compose.yml` / Kubernetes manifests bind DB/cache/queue ports to `0.0.0.0` without passwords | Read ALL compose files/manifests → check if ports are host-bound → check if services require authentication (`--requirepass`, `POSTGRES_PASSWORD` strength, TLS) | 1 |
| A17 | **Dev mode / debug enabled in production** | `DEV_MODE=true`, `DEBUG=*`, `ENABLE_CONSOLE=true`, verbose error logging enabled by default | Search config for `dev_mode`, `debug`, `console`, `verbose` flags → check if they are gated by environment (prod vs dev) | 1, 4 |
| A18 | **Destructive env var trigger** | Environment variables that trigger dangerous operations: `TRUNCATE_DATABASE`, `DROP_TABLES`, `RESET_*`, `WIPE_*` | `grep -rn "TRUNCATE\|DROP\|RESET\|WIPE\|DESTROY"` in config → check if they're protected by confirmation or environment guards | 4 |
| A19 | **Missing error handling at API boundaries** | API resolvers/handlers without try/catch → uncaught exceptions leak stack traces or crash the process | Count `catch` blocks vs resolver/handler count → if ratio is low, missing error handling is systemic | 4 |
| A20 | **Error message info leakage** | Raw `error.message` or `error.stack` returned in HTTP/GraphQL responses | `grep -rn "error.message\|error.stack\|err.message"` in response handlers → check if errors are sanitized before sending to client | 4 |
| A21 | **Crypto key generation endpoint without auth** | Endpoints that generate private keys, spending keys, signing keys, or secrets via HTTP without authentication | `grep -rn "getSpendingKey\|generateKey\|getPrivateKey\|createKey"` → check auth on each → key generation must be localhost-only or authenticated | 1, 4 |
| A22 | **Exception-swallowing security filter** | Security filters (auth, rate limit, access control) that catch Exception and silently continue → bypass on any error | Read every filter/interceptor's catch block → verify it sends an error response or re-throws, not just logs | 3, 4 |
| A23 | **Reflection-based deserialization with user-controlled type** | User input selects a class/type via `Class.forName()`, `valueOf()`, or `getContract()` → reflection instantiation with `setAccessible(true)` | `grep -rn "setAccessible\|Class.forName\|valueOf\|getContract"` → trace the type string back to user input → check if constrained | 3, 4 |
| A24 | **Unbounded in-memory maps from user requests** | Maps/caches (`ConcurrentHashMap`, `HashMap`) that grow from user-created entries (filters, sessions, subscriptions) without max size | `grep -rn "ConcurrentHashMap\|HashMap.*new"` → check if entries are added from user requests → verify max size or eviction exists | 4 |
| A25 | **Mass assignment** | ORM model populated from raw user JSON without field allowlist → attacker sets `role`, `isAdmin`, `price`, `ownerId` | `grep -rn "\.create(req\|Object.assign.*req\|merge.*body\|set(body"` → check if field allowlist or DTO validation constrains accepted keys | 1, 3, 4 |
| A26 | **CORS origin reflection** | `Access-Control-Allow-Origin` echoes back the `Origin` header + `Access-Control-Allow-Credentials: true` → any origin can make credentialed requests | `grep -rn "Access-Control-Allow-Origin\|allowedOrigins\|cors("` → check if origin is reflected or if wildcard is used with credentials | 1, 3 |
| A27 | **API version downgrade** | Older API versions (`/v1/`, `/v2/`) lack security controls added to newer versions — auth, rate limiting, input validation | `grep -rn "v1\|v2\|version"` in routes → test all discovered versions for the same endpoint → compare auth and validation behavior | 1, 4 |
| A28 | **Webhook signature bypass** | Webhook endpoint does not verify HMAC signature, uses timing-vulnerable comparison, or falls back to no-auth when secret is empty | `grep -rn "webhook\|signature\|hmac"` → check if verification is skipped when `secret == ""` or when header is missing → test with empty/invalid signature | 1, 3, 4 |
| A29 | **JWT kid / jku header injection** | JWT `kid` header used in DB query or file path without sanitization (SQLi or path traversal); `jku` / `x5u` header points to attacker-controlled key server | Decode any JWT in the app → check if `kid` is used in a lookup → test `kid: "' OR '1'='1"` (SQLi) and `kid: "../../../../etc/passwd"` (path traversal); test `jku` pointing to external URL | 3, 4 |
| A30 | **Theme/template path injection** | Server-controlled response keys used as file system paths without sanitization → arbitrary file write or read (e.g., archive extraction or template migration where server supplies file names) | `grep -rn "writeFile\|readFile\|createWriteStream"` → check if path includes server-supplied or user-supplied key → verify path normalization and containment | 1, 3 |
| A31 | **Prototype pollution via deep merge** | `_.merge()`, `deepmerge()`, or recursive copy with user-controlled nested keys including `__proto__` → properties injected into all objects | `grep -rn "_.merge\|deepmerge\|Object.assign"` → check if user input reaches nested merge → test `{"__proto__":{"isAdmin":true}}` → check for gadgets (Pug, lodash templates) | 3, 4, 5 |
| A32 | **XXE via file upload** | File upload endpoint accepts XML-containing formats (SVG, DOCX, XLSX, PPTX, XML config) and parses them without disabling external entity resolution | `grep -rn "multer\|upload\|multipart"` → check accepted MIME types → if XML formats accepted, check parser config for `FEATURE_EXTERNAL_GENERAL_ENTITIES` or equivalent → test SVG upload with `<!DOCTYPE x [<!ENTITY xx SYSTEM "file:///etc/passwd">]>` | 1, 3 |
| A33 | **File-identifier path traversal** | User-supplied `fileId`, `fileName`, `templateId`, or similar "identifier" fields are passed to path-building functions (`filepath.Join`, `path.join`, `os.Open`, `GenerateFilePath`) without stripping separators or traversal components. Because these params look like identifiers rather than paths, developers skip path sanitization. `filepath.Join("/base", "/etc/passwd")` in Go returns `/etc/passwd` — absolute paths completely override the base. | `grep -rn "filepath.Join\|path.join\|os.Open\|ReadFile\|WriteFile\|GenerateFilePath"` → trace each call's arguments back to their source → flag any argument that originates from user-supplied fileId/fileName/templateId → verify `filepath.Base()` or equivalent stripping is applied before join | 1, 2, 3 |
| A34 | **Arbitrary file deletion via unvalidated cleanup path** | Cleanup / garbage-collection code reads file paths from execution records, job metadata, or user-supplied filenames and passes them directly to `os.Remove`, `fs.rm`, `unlink`, or equivalent without path validation. Attacker supplies crafted filename (e.g., `../../app/config/secrets.yaml`) at creation time; cleanup later deletes the target file. | `grep -rn "os.Remove\|fs\.rm\|unlink\|os\.Unlink\|rimraf"` → check if the path argument originates from a stored record whose filename was user-supplied → verify the path is resolved to a safe base directory before deletion | 1, 3, 4 |
| A35 | **Cross-tenant IDOR via missing org/workspace ownership check** | Service methods look up resources by ID alone (`GetFlowByID`, `GetByID`, `FindOne({id})`) without verifying that the returned resource belongs to the requesting tenant's org/workspace. Any authenticated user who knows or guesses another tenant's resource ID can access or execute it. Most common in sub-flow execution, asset references, template lookups, and shared-file references. | `grep -rn "GetBy.*ID\|FindByID\|findOne.*id\|GetFlowByID\|fetchById"` → check if there is an explicit org/workspace ownership assertion on the returned object after retrieval → look for patterns like `if result.OrgID != requestingOrgID { return error }` | 1, 3, 4 |
| A36 | **Auth middleware registration order bug** | In web frameworks that apply middleware per route group (Gin, Echo, Fastify, Express, Hono), a route registered BEFORE `api.Use(authMiddleware)` runs without authentication — even if all subsequent routes are protected. Special-purpose endpoints (webhooks, callbacks, hooks) are frequently registered outside the guarded group to avoid auth friction, inadvertently making them public. | Read the main router/app file → map route registration order → identify any route registered before `app.Use(auth*)` or outside the protected group → test the endpoint with no Authorization header | 1, 3, 4 |

### How to Expand the Library

After each audit, for every finding ask:
1. **Already in library?** → No action
2. **New abstract pattern?** → Add with generic detection strategy
3. **Improves existing archetype?** → Add the new detection technique

The library should grow with each audit until it covers all common patterns — then the skill becomes stable and only needs updates when new vulnerability classes emerge.

---

## Rules

1. **Never accept a sanitizer as blocking without attempting bypass** — enumerate at least 3 bypass techniques per sanitizer before declaring it blocked.
2. **Assume all data is malicious** — do not give developer intent the benefit of the doubt.
3. **Configuration-dependent vulnerabilities are still valid** — "only exploitable when webhook_secret is empty" is a real finding if that is a common or default state.
4. **Compound chains count** — two medium findings that together reach critical impact must be reported as a combined critical.
5. **Always provide a PoC** — a finding without a reproducible test is not reportable.
6. **Simulate the full exploit** — do not stop at "there is an injection point." Walk through whether the attacker achieves real impact.
7. **Deprioritize noise** — if the blast radius does not reach RCE, PrivEsc, Data Exfil, or hard DoS, mark as low/informational and move on.
8. **Type confusion is a first-class check** — at every API boundary, test wrong types explicitly.
9. **Cryptographic findings require implementation analysis** — algorithm name alone is insufficient; check IV use, key derivation, nonce reuse, and timing.
10. **Second-order sinks are in scope** — trace data through storage and retrieval, not just within a single request.
11. **Data doesn't only come from "user input"** — trace data from HTTP request structure, URL routing, search parameters, pagination cursors, queue payloads, chain events, external fetches, and database re-reads. Each is a potential attack vector.
12. **Every finding gets a 0–100 confidence score** — use the scoring formula to prioritize and to communicate certainty to report readers.
13. **Iterate until coverage is complete** — one pass is never enough. Use the iterative deepening loop to systematically expand coverage.
14. **Always audit infrastructure metadata files** — Hasura metadata, Docker configs, Kubernetes manifests, Terraform files often contain overly permissive defaults that equate to critical findings.
15. **Trace enum definitions to their SQL usage** — an enum that looks safe in GraphQL may contain raw SQL expressions that are interpolated unsafely.
16. **Read every custom sanitizer line-by-line** — `safeString()` or `sanitize()` functions often only handle one edge case (null bytes) while missing entire vulnerability classes (XSS, SQLi).
17. **Map all queue dispatch endpoints** — every `dispatch*/add*/publish*` call is a potential DoS vector if the calling endpoint lacks auth + rate limiting.
18. **Test address/ID decoding at API boundaries** — `decodeAddress()`, `base58decode()`, `Buffer.from(cursor)` can throw uncaught exceptions → application crash DoS.
19. **Web research improves the skill, not the findings** — search for new patterns, bypass techniques, and vulnerability classes to add to the Phase checklists and Archetype Library. The skill gets better; the methodology stays stable.
20. **Check for dead security code** — security features that are declared but never wired into the request flow provide zero protection. Verify that rate limiters are read, auth decorators are applied, and CSRF tokens are validated.
21. **Always analyze deployment configs** — `docker-compose.yml`, `Dockerfile`, Kubernetes manifests, Terraform, CI/CD pipelines are part of the attack surface. Exposed ports, missing auth on services, secrets in build args, and `.env` files mounted into containers are all findings.
22. **Audit every admin dashboard** — Bull Board, pgAdmin, Hasura Console, Swagger UI, Flower, Redis Commander. Check if auth middleware exists BEFORE the dashboard route. An unauthenticated admin panel is Critical severity.
23. **Count try/catch blocks vs resolver count** — if the ratio is low (e.g., 2 catches for 16 resolvers), error handling is systemically missing. Every unhandled exception is both a DoS vector and an info leakage vector.
24. **Review every error response construction** — `res.status(500).json({ error: error.message })` leaks internal state. Check all error handlers for raw message/stack exposure.
25. **Treat environment variables as attack surface** — `TRUNCATE_DATABASE=true`, `ADMIN_MODE=true`, `DEBUG=*` can be weaponized if an attacker gains env access (container escape, CI/CD compromise, SSRF to metadata service).
26. **Ask: what am I NOT looking at?** — after each pass, explicitly list the categories you ignored (infrastructure, deployment, tests, CI/CD, documentation, third-party integrations, client-side code, mobile apps). Then audit at least one of them. The highest-severity findings often hide in places nobody thinks to look.
27. **Read documentation before code** — README, API specs, and architecture docs reveal the developer's security assumptions. Every gap between documented behavior and actual implementation is a candidate finding.
28. **Always test CORS** — check if the `Origin` header is reflected in `Access-Control-Allow-Origin`, if `null` origin is accepted, and if `Access-Control-Allow-Credentials: true` is set with non-allowlisted origins. Reflected origin + credentials = account takeover via cross-origin request.
29. **Test for mass assignment on every create/update endpoint** — add unexpected fields (`role`, `isAdmin`, `ownerId`, `verified`, `price`) to request bodies and check if they are persisted in the response. Frameworks with auto-binding are vulnerable by default.
30. **Prototype pollution is first-class** — test `__proto__`, `constructor.prototype`, and `constructor` keys in all deep-merge paths, query strings, and JSON bodies. Find the gadget (Pug, lodash template, JSON serializer) that converts pollution into impact.
31. **Document negative findings explicitly** — stating "X was checked and is not exploitable because Y" prevents re-investigation in future passes and proves coverage completeness.
32. **Check HTTP method override** — `X-HTTP-Method-Override`, `X-Method-Override`, and `_method` query/body parameters can convert a GET to a DELETE or POST, bypassing method-specific auth guards and CSRF protection on servers that honor them.
33. **Treat `fileId`/`fileName`/`templateId` as paths, not identifiers** — any field whose value reaches a filesystem path builder (`filepath.Join`, `path.join`, `os.Open`) must be sanitized with `filepath.Base()` or equivalent, regardless of whether the field name implies it is an ID. In Go, `filepath.Join(base, userInput)` where `userInput` starts with `/` completely overrides the base.
34. **Verify resource ownership after every `GetByID` call** — every service-layer lookup by ID must assert that the returned resource's org/tenant/workspace matches the requester's context. Missing this check is an IDOR even when the ID is a UUID.
35. **Check route registration order for auth middleware** — in all major Go/Node.js frameworks, a route registered before `app.Use(authMiddleware)` or outside the protected group runs without auth. Read the main router file top-to-bottom and verify every sensitive route is enclosed within the auth-protected group.
36. **SSRF sources include API response URLs** — a `fetch(response.data.url)` or URL fallback from a third-party API response is SSRF if the response origin is attacker-influenced or the URL is passed without private-IP/redirect validation. Do not limit SSRF scanning to direct user-input URL fields.

---

Start with **Before Phase 1** (read documentation), then **Phase 1** immediately. Complete each phase fully before proceeding to the next. If `output=` was specified, write each phase to a numbered file (e.g., `01-threat-model.md`, `02-data-flow-mapping.md`, `03-taint-tracking.md`, etc.).

**Consult the Phase 9 Archetype Library from Phase 1 onwards** — search for each archetype as you analyze components, not just at the end. After Phase 7, execute Phase 8 and loop back as needed. After the audit, add any new archetypes discovered to Phase 9.
