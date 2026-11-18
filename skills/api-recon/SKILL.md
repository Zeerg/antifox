---
name: api-recon
description: Invoke this skill when collecting a website's API endpoints.
---

# API Recon (frontend endpoint reconnaissance)

Under **authorized** conditions, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI feature trigger points** (tabs, modals, table actions, etc.).

---

## Boundaries & prohibitions (Agent must read · violation = out of scope)

This skill performs **API / parameter-surface reconnaissance only** — it is not a vulnerability-discovery or exploitation phase.

### Scope

| Scope | Allowed | Forbidden |
|---|---|---|
| **Targets** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege-escalation/brute-force/fuzz vulnerabilities, packet tampering, destructive actions |
| **Auth** | Hook + stub/mock to bypass **client-side** login gates | Asking the user for or guessing credentials; submitting real login forms |
| **Runtime** | Hook endpoints without credentials; use mock responses to get the SPA into its post-login shell | Flows that require a real backend session to proceed |

### Credential-free dynamic analysis (Phase 3 default)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** login, permission, menu, and other bootstrap endpoints;
2. Return mock bodies for business query endpoints with **correct structure, success business code, and data that may be empty**;
3. Let the frontend render post-login pages even without a backend or under 401s, triggering more XHR/fetch/WebSocket calls;
4. **Empty data, blank tables, and placeholder UI are all expected** — do not pivot to real logins or vulnerability testing because of them.

**In one line**: use mocks to expand frontend routes and component mounts, **recording outbound requests only**; what the backend returns doesn't matter — what matters is **which endpoints the frontend still calls**.

### Hard process prohibitions

| Forbidden | Alternative |
|---|---|
| grep/curl/Read the main entry `index-*.js` for API paths before Phase 1 completes | Run `OUTDIR/harvest_static.py` |
| Hand-writing `extract_apis.py`-style scripts instead of harvest | Modify `OUTDIR/harvest_static.py` and re-run it |
| Repeating the same grep/command after ≥2 failures | Change strategy: read tool_logs, edit harvest, check the reference |
| Skipping gates A/B and running `scripts/` originals directly | Copy to OUTDIR and adapt to the target |
| Real usernames/passwords, OTP, OAuth, or other auth | stub/mock (see above) |
| Skipping stubs "to get real data" and doing privesc/injection testing | Record outbound only — that's the recon boundary |
| Deletes, sensitive-data exports, bulk writes, or other irreversible actions | Same during coverage clicking |
| Claiming all pages/endpoints captured without finishing runtime + dynamic enumeration | See "Definition of done" or annotate the limitation |
| Claiming all parameters known without the parameter trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Inferring required/optional from a single runtime sample | Multi-sample diff or validation rules/error inference |

---

## Two-layer model + run modes

| Layer | Output | Limit |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, draft routes, field candidates at call sites | No HTTP methods; params need Phase 1b; misses runtime-assembled URLs |
| **Runtime** (live session) | Methods + bodies + responses + dynamic URLs + WS/SSE; multi-sample diff completes params | Pages must actually render to fire requests; one sample can't determine required/optional |

| Run mode | Engine | Use for |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Clicking tabs/modals/tables — deeper feature coverage |
| **both** | depth then coverage | Most complete, slowest |

**Parameter methodology** (no universal script): paths via harvest/regex; parameters via **anchor-window expansion + UI binding chains + multi-sample diff + error inference** (grep recipes in [reference.md](reference.md) section J).

---

## Definition of done

All must hold before claiming recon complete:

- [ ] **Static**: Phase 1 harvest produced `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: at least depth or coverage; coverage/both requires **working hooks + the dynamic-enumeration loop**
- [ ] **Inside the shell**: business paths render, not `/login` (watch hash routing)
- [ ] **Parameters**: coverage/both completed the parameter trigger matrix + `param_samples.json`; Phase 5 merged `params_merged.json`
- [ ] **Depth** (if module pages came back blank): Phase 4 permission-tree restoration and re-run until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Deliverables**: Phase 5 outputs complete (see the Phase 5 output table); `insert_assets` wrote the service and endpoint assets

---

## Scripts & gates

`scripts/` are reference templates only — **never** run the originals and treat output as final.

**Rule**: read first → adapt to the target → write into `OUTDIR` (e.g. `recon/`) → log `CHANGES.md`; if a script doesn't fit, rewrite per the methodology, borrowing only its structure.

| Gate | When | Reference script → OUTDIR copy | Common required edits |
|---|---|---|---|
| **A (static)** | After Phase 0, before the **first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | **Most sites run fine with default regexes**; only on manifest/dialect mismatch change endpoint regexes, webpack/Vite `publicPath`, MPA exclude/cookie |
| **B (runtime)** | After Phase 2, before depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success values, stubs, login regex, api prefix, hash/history |

**Mandatory SPA order** (not reorderable; phase numbers beat "explore first, script later"):

| Step | Must | Must not |
|---|---|---|
| After Phase 0 | Next Bash = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy script → small edits as needed → **run immediately** | Hand-extract APIs first, then decide about harvest |
| Before Phase 1 done | Validate output with `wc -l`; on 404s fix harvest and retry | Hand-write extract scripts; re-grep URLs not yet downloaded |
| From Phase 1b | grep only `OUTDIR/js/*.js` | Use the main bundle instead of harvest output |

- ✅ Copy `harvest_static.py` → (optionally) tweak regex → **run immediately**
- ❌ curl the main bundle → grep repeatedly → write a throwaway extract → only then harvest
- **MPA**: after Phase 0 the next Bash = `python3 OUTDIR/spider_mpa.py ...`

---

## Tooling & output constraints

| Constraint | Rule |
|---|---|
| Large files | `index-*.js` over 100KB must **never** be Read/grepped into context; batch-process with OUTDIR scripts |
| grep output | Always `| head -20` or `-m 5`; keep only path summaries in the conversation, never paste bundle fragments |
| Validation | Use `wc -l`, `ls | wc -l`; never Read whole directories |
| Initial regex probe | Optional, ≤1 pass, only on ≤50KB chunks or HTML; canonical static results come from harvest |
| reference | Recipes/templates/troubleshooting live in [reference.md](reference.md) — don't re-inline them |

---

## Execution roadmap

```
Phase 0 classify + OUTDIR
  → Gate A → Phase 1 harvest (★ run immediately ★)
  → Phase 1b parameter reversing
  → Phase 2 three auth gates → config.json
  → Gate B → Phase 3 runtime + parameter matrix
  → Phase 4 permission tree (when needed) → re-run Phase 3
  → Phase 5 merged report + insert_assets — batch-insert ALL discovered service/endpoint API assets; none may be omitted
```

Check off in order; **never enter the next phase with the previous one unfinished**.

1. [ ] **Phase 0**: probe SPA vs MPA; create `OUTDIR` → [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: copy script → harvest **immediately** → `wc -l` validate → [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: anchor expansion + binding layers → `param_candidates.json` → [Phase 1b](#phase-1b--parameter-reversing)
4. [ ] **Phase 2**: three auth gates → `config.json` → [Phase 2](#phase-2--three-auth-gates)
5. [ ] **Gate B**: adjust runtime scripts → [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm inside the shell; parameter trigger matrix → `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree → patch stubs → re-run Phase 3 → [Phase 4](#phase-4--permission-tree-restoration)
8. [ ] **Phase 5**: merged outputs + report + `insert_assets` → [Phase 5](#phase-5--merge--report)

---

## Phase 0 — classification

Fetch the entry HTML and **create `OUTDIR`** (never modify the skill's own `scripts/`):

- **SPA**: empty shell + `<div id=app>` + chunks → Phase 1–5
- **MPA**: SSR + `<form>`s, no endpoint bundle → after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt`, `api_inline.txt`. If a SPA shows forms ≈ 0 → move to Phase 1.

---

## Phase 1 — static

Follow [Scripts & gates](#scripts--gates) · [Tooling & output constraints](#tooling--output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parse HTML scripts → webpack/Vite manifest → download all lazy chunks → produce `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- chunk count vs manifest: on 404s fix harvest and retry — don't hand-curl chunks one by one
- too few `api_static.txt` hits → loosen the endpoint regex inside OUTDIR and re-run (see reference)

### Phase 1b — parameter reversing

Paths come from Phase 1; parameter fields need separate recon. grep rules per [Tooling & output constraints](#tooling--output-constraints).

**Completion bar**: for important endpoints you can answer — field names, transport location, inferred types, required/optional, sample values, confidence.

#### 1b.0 — transport shape

| Shape | Where params live | Static-first look |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` next to the path anchor |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Classic form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path params | `/user/:id` | route table + `useParams` / `$route.params` |
| Encrypted/signed | wrapped in `sign`/`data` | hook the encryption function's inputs (reference section D) |

Output: each endpoint tagged `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — anchor-window expansion

Anchor on known paths and widen the window to find the payload-assembly object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clues |
|---|---|
| axios instance | `data` / `params` |
| Unified request | interceptors inject global fields |
| OpenAPI client | generated method signatures |
| React Query / SWR | hook's second argument |
| Vue composable | composable inputs |

Type residue: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

→ `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — binding layers

```
Form field → onFinish/handleSubmit → transform → API payload
```

| Binding source | Technique |
|---|---|
| Form submit | follow submit → transform → API |
| Table search | `getFieldsValue()` → `params` |
| Routing | `:id` / `?tab=` |
| Interceptors | global `tenantId`, pagination, sign |
| Enum selects | `options` → API enum values |

From DevTools, walk the call stack up from `fetch`/`XHR.send` to the assembly function.

#### 1b.3 — the three assembly questions (≠ Phase 2's three auth gates)

| Question | What to answer |
|---|---|
| **Assembly** | where the payload is built, transform traces |
| **Validation** | required, patterns, enums |
| **Transport** | path / query / body / multipart / headers |

While at the interceptor gate (Phase 2), also read globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 — handoff to Phase 3

Candidate fields come from static/binding layers; **required/optional/conditional dependencies** need the Phase 3 parameter matrix + diff + Phase 5 error inference.

---

## Phase 2 — three auth gates

grep inside `OUTDIR/js/` (with `head`), write results into `config.json` (recipes in reference):

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | how is "logged in" determined? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | what triggers the redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Never treat a localStorage key name as a credential — confirm from chunks/request chains.

**Exit = Gate B**: conclusions land in `config.json`, and `OUTDIR/runtime_harvest.js` / `preload.js` get adjusted.

### Phase 2b — API observation (optional)

Use the OUTDIR copy of `preload.js` to confirm session key names, Authorization, nested API URLs:

| Setting | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | header observation |
| `extractUrlsFromResponse: true` | sub-APIs inside responses |
| `observe.storageReads/cookieReads: true` | backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

Each coverage round exports: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — runtime

Requires Gate B passed; follow [Boundaries & prohibitions](#boundaries--prohibitions-agent-must-read--violation--out-of-scope) · the credential-free mock strategy.

Set `"runtimeMode": "depth" | "coverage" | "both"` in `config.json` (template in reference).

### Hooks and stubs (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 precise | auth/permission/bootstrap stubs | pass first-screen auth |
| L2 negative fix | all JSON responses | not-logged-in code → success |
| L3 fallback | `/api` etc. not hit by L1 | empty success body to expand UI |

- **depth**: fake auth + `forward` rewrites business codes + `stubs`; walk `routes` (hash/history); produce `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or a Userscript)

Verify: `window.__API_RECON_PRELOAD__` exists; business paths don't bounce to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — coverage dynamic enumeration (mandatory)

1. Main nav/sidebar — click each item, wait 1–3s for network
2. Tabs — `role=tab`, `.ant-tabs-tab`
3. Tables — first-row view/edit/details
4. Toolbars — export, filter, create (**avoid irreversible deletes**)
5. Per module — merge APIs/routes
6. SPA — controlled `pushState` for `routes.txt` paths not yet covered (forbidden on MPA)

**Parameter trigger matrix** (mandatory): record once per operation type per module, **diff across samples**:

| Operation | Usually adds |
|---|---|
| List first render | pagination + default filters |
| Clicking search | keyword, filter |
| Advanced filter | more optionals |
| Create/edit | the full entity |
| Bulk/export/sort | `ids[]`, `exportType`, `sortField` |

**Outbound bodies/headers remain real under stubs** — trust the request. Record → `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: 3a depth first, then 3b coverage

---

## Phase 4 — permission-tree restoration

**Trigger**: module pages blank / every route fires only bootstrap calls (e.g. locale) → the content gate isn't passed.

| Symptom | Meaning |
|---|---|
| Got into the shell | render + interceptor gates passed |
| Sidebar missing items / clicks render blank | stub shape wrong or permission codes incomplete |
| Same few APIs on every route | `v-if permission` not satisfied |
| `routes.txt` far smaller than the bundle | must complete from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) → `getResultTree` → `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

Stub checks: outer `response_code` matches the interceptor gate; flat codes align with the tree; `routes` covers every `route_map` link.

After updating `config.json`, **re-run Phase 3**. Large SPAs may need `waitUntil`, `routeTimeout`, `perRouteMs` tuning (reference sections A3/I).

---

## Phase 5 — merge & report

### Output table

| File | Phase | Contents |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | static bundle + paths |
| `param_candidates.json` | 1b | static parameter-field candidates |
| `config.json` | 2 | three gates + runtime config |
| `runtime_api.json` | 3a | depth detail recording (incl. WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | multi-samples, click log, detail |
| `route_map.json` etc. | 4 | permission-tree intermediates (if run) |
| `params_merged.json` | 5 | merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | routes, APIs, params, features, limitations |
| **insert_assets** | 5 | write all service/endpoint assets into the asset store |

### 5b — parameter merge

Diff `param_samples.json` — **no universal merge script**. Confidence rules in reference J7 (high/medium/low/to-be-triggered).

### 5c — error inference

Within authorization you may send incomplete requests to read 400s (**parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Watch for `data` wrappers, `variables`, and pre-encryption `bizData`.

The report must note: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary of deltas vs the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

More fields and grep recipes in [reference.md](reference.md).

---

## General notes

- **Framework-agnostic**: webpack/Vite/Angular lazy-load all work the same way
- **Transports**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetches can be recorded; RSC/Server Actions aren't fully enumerable
- **Blind spots**: JSVMP, WASM, HMAC/mTLS strong checks → static only + annotate the limitation
- **Parameter blind spots**: conditional linkages, hidden params, WASM-assembled payloads → mark "to-be-triggered" / "unreachable"
- **Static is the safety net**: when runtime is blocked, static still enumerates endpoints

---

## Additional resources

- Grep recipes, `config.json` templates, troubleshooting, hooks, parameter-reversing section J, site_map template: **[reference.md](reference.md)**
- Reference script paths in the [Scripts & gates](#scripts--gates) table
