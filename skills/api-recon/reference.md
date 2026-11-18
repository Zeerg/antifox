# api-recon — reference manual

Grep recipes, `config.json` templates, and troubleshooting. All greps run against the `js/` directory. For single-line bundles, `js-beautify` or `sed 's/}/}\n/g'` first helps, though raw grep with a context window usually suffices.

## Script notes

Every file in `scripts/` is a **reference template** — adapt it to the target site before running. Typical changes:

| Script | Common adjustments |
|---|---|
| `harvest_static.py` | endpoint regexes, webpack/Vite manifest parsing, micro-frontend publicPath, retry/concurrency |
| `runtime_harvest.js` | neutralize field names and success values, stub match rules and body structure, routes source, WS recording, `waitUntil`/`routeTimeout`/`proxy` |
| `preload.js` | `loginPathRe`, L1 stubs, `neutralize.fields`, `apiPattern`, whether to enable L3, `recordDetail`, `observe.*`, `neutralizeVueRouter` |
| `spider_mpa.py` | `--exclude` destructive links, cookies, depth/max, same-origin filtering |
| `extract_route_map.py` | `routeMap` / `routeLink` regexes, KEY naming pattern |
| `build_perm_tree.py` | `userRouteAuth` parsing, `ROOTS`/`PREFIX_PARENT` hierarchy heuristics, stub outer field names |
| `config.json` | unified entry point for all site-specific params above |

Keep adjusted files in the task working directory (e.g. `recon/`) and note the concrete changes vs the reference scripts in the report.

---

## A. The three auth gates

### A1. Render gate — "how does it know I'm logged in?"

```bash
grep -rhoaE '.{0,40}(isLogin|isAuthenticated|loggedIn|hasLogin|requireAuth)\b.{0,80}' js | head
grep -rhoaE 'function (getUser|getToken|getAuth)[0-9]?\([^)]*\)\{.{0,200}' js | head
grep -rhoaE '(localStorage|sessionStorage)\.getItem\("[^"]+"\)' js | sort -u
grep -rhoaE '(Cookies?|cookie)\.(get|load)\("[^"]+"\)' js | sort -u
grep -rhoaE '\batob\(|JSON\.parse\(|jwt|decode' js | head
```

Trace `isLogin = f(getUser())` → `getUser = decode(storage.read(KEY))` and determine the **storage key**, **container** (Cookie vs localStorage), and **encoding**:

| Encoding | config forge method |
|---|---|
| Plain string / `"1"` / token | `"value": "anything-truthy"` |
| `JSON.parse(x)` | `"value": "json:{\"id\":1,\"username\":\"admin\"}"` |
| `JSON.parse(atob(x))` | `"value": "b64json:{\"id\":1,\"username\":\"admin\"}"` |
| JWT | unsigned/`alg:none` JWT, or sign with a key from the bundle |
| Encrypted (SM2/AES/RSA) | find the hardcoded key; forge if the render gate only needs a decodable blob; otherwise fall back to static |

→ write into `cookies` / `localStorage`.

### A2. Interceptor gate — "what triggers the /login redirect?"

```bash
grep -rhoaE '.{0,60}(interceptors\.response|axios|request\.use).{0,120}' js | head
grep -rhoaE '.{0,40}(response_code|errcode|errno|\bcode\b|\bret\b|\bstatus\b)\s*[=!]==?\s*[\-0-9]{1,4}.{0,60}' js | head -20
grep -rhoaE '.{0,40}(未登录|请重新登录|登录已过期|unauthorized|登录失效|授权|token.{0,10}invalid).{0,40}' js | head
grep -rhoaE '.{0,30}(location\.href|router\.(push|replace)|navigate)\([^)]*login[^)]*\)' js | head
```

Determine: **field name**, **success value** (usually `0` or `200`), and the **failure value that triggers the redirect**. Verify with a junk session:

```bash
curl -sk -X POST -H 'Cookie: <fakekey>=junk' https://target/api/<protected> -d '{}' -H 'Content-Type: application/json'
```

→ write into `neutralize.fields` + `neutralize.success`.

### A3. Content gate — "where do menus/permissions come from?"

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl|resource|nav)[^"]*"' js | sort -u
grep -rhoaE '.{0,30}(menus|permissions|menuList|routeList|authList|role_permissions)\b.{0,120}' js | head
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|hasPermission|checkAuth' js | head
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head
```

**Two layers of data** (typical enterprise admin):

| API | Typical payload | Consumer |
|---|---|---|
| `.../role_permissions` | `{ permissions: string[], role_type }` | route guards, button-level ACL |
| `.../permissions/all` | `tree[{ code, position, children }]` | sidebar menu rendering |
| in-bundle `userRouteAuth` | `{ CODE: { url, name? } }` | code → frontend path |
| in-bundle `routeMap` | `{ KEY: { name, link } }` | alias resolution (webpack `o.DASHBOARD`) |

Read the consumer code to confirm: how `getResultTree(tree, permissions)` filters, and which field `v-if` / `hasAuth(code)` checks.

**Manual forge** (small sites): build a permissive payload → `stubs`.

**Full permission-tree restoration** (large sites — sidebar/submodules still blank): see **section I**.

---

## B. config.json template

```json
{
  "baseUrl": "https://target/",
  "runtimeMode": "both",
  "chromium": "/usr/bin/chromium",

  "cookies": [
    { "name": "auth", "value": "b64json:{\"id\":1,\"username\":\"admin\",\"role\":\"admin\",\"func\":{},\"permissions\":[\"*\"]}" }
  ],
  "localStorage": { "token": "faketoken", "isLogin": "1" },

  "neutralize": {
    "fields": ["response_code", "code", "errno", "ret", "status"],
    "success": 0,
    "flags": { "success": true, "message": "ok" }
  },
  "forward": true,
  "loginUrlPattern": "/login",
  "apiPattern": "/api/|/rest/|/graphql",

  "mockTier": "L1+L2",
  "recordDetail": true,
  "observe": {
    "storageReads": false,
    "cookieReads": false,
    "xhrHeaders": true
  },
  "neutralizeVueRouter": true,
  "stubs": [
    {
      "match": "permissions/all|/menu|role_permissions",
      "body": {
        "response_code": 0, "code": 0,
        "data": {
          "permissions": ["*"],
          "menus": [
            { "name": "dashboard", "path": "/dashboard", "show": true, "children": [] },
            { "name": "alert", "path": "/alert", "show": true, "children": [] }
          ]
        }
      }
    }
  ],

  "explore": {
    "clickTabs": true,
    "clickTables": true,
    "pushStateFallback": true,
    "maxMenuItems": 50
  },

  "routes": ["/dashboard", "/alert", "/asset", "/device", "/report", "/config", "/system"],
  "waitMs": 1500, "perRouteMs": 900, "headless": true,
  "waitUntil": "domcontentloaded",
  "routeTimeout": 12000,
  "proxy": "",

  "captureResponses": true, "recordWs": true, "respMax": 600
}
```

Field notes:
- `runtimeMode`: `depth` (Puppeteer), `coverage` (browser MCP), `both`
- `cookies[].value` prefixes: `b64json:` → base64(JSON); `json:` → raw JSON; no prefix → literal
- `forward: true` forwards real requests while rewriting code fields; `false` = fully offline stub
- `mockTier`: preload tiers enabled in coverage mode, e.g. `L1+L2`, `L1+L2+L3`
- `routes` comes from `routes.txt`; after forging menus the harness auto-appends `<a href>`
- `captureResponses` / `recordWs` only apply in depth mode
- `waitUntil`: use `domcontentloaded` on large SPAs; `networkidle2` tends to hang
- `routeTimeout`: per-route `page.goto` timeout (ms)
- `proxy`: Puppeteer `--proxy-server`; `HTTP_PROXY` / `HTTPS_PROXY` env vars also work

### B1. Dual-stub template (role_permissions + permissions/all)

```json
"stubs": [
  {
    "match": "role_permissions",
    "body": {
      "response_code": 0,
      "data": {
        "permissions": ["MONITOR", "MONITOR_ALERT", "THREAT", "ASSETS_RISK"],
        "role_type": "SUPER_ADMIN"
      }
    }
  },
  {
    "match": "permissions/all",
    "body": {
      "response_code": 0,
      "data": [
        {
          "code": "MONITOR",
          "position": 1,
          "children": [
            { "code": "MONITOR_ALERT", "position": 1, "children": [] }
          ]
        }
      ]
    }
  }
]
```

Outer field names (`response_code` / `code` / `data`) must match the A2 interceptor gate; `permissions` must cover every leaf code in the tree.

---

## C. coverage mode: preload config

Edit the `CONFIG` object at the top of `scripts/preload.js`, or substitute it before CDP injection:

```javascript
const CONFIG = {
  loginPathRe: /\/(login|signin)(\/|$|\?)/i,
  mockTier: 'L1+L2',
  forward: true,
  recordDetail: true,
  extractUrlsFromResponse: true,
  neutralizeVueRouter: true,
  observe: { storageReads: false, cookieReads: false, xhrHeaders: true },
  neutralize: { fields: ['response_code', 'code'], success: 0 },
  stubs: [ /* same as config.json stubs */ ],
  apiPattern: /\/(api|apis|v\d+|dev|internal|graphql)\//i,
};
```

Verify: `window.__API_RECON_PRELOAD__ === true` and the pathname stays stable.

Export the recorded results:

```javascript
JSON.stringify({
  apis: [...window.__API_RECON_LOG__],
  detail: window.__API_RECON_DETAIL__,
  routes: [...(window.__API_RECON_ROUTES__ || [])],
  observe: window.__API_RECON_OBSERVE__,
}, null, 2)
```

---

## D. preload / runtime hook capabilities

Built-in browser hook capabilities of preload (coverage) and runtime_harvest (depth), with coverage:

| Hook capability | Value for API discovery | Covered |
|---|---|---|
| Hook fetch / XHR.open | record request URL/method | ✅ `recordDetail` + `__API_RECON_LOG__` |
| Hook XHR.setRequestHeader | discover Authorization and other headers | ✅ `observe.xhrHeaders` |
| Hook localStorage/cookie reads | confirm session key names | ⚠️ optional `observe.storageReads/cookieReads` |
| Vue route capture | complete frontendRoutes | ✅ `__API_RECON_ROUTES__` (loaded routes) |
| Vue route-guard neutralization / login-redirect block | keeps modules mounted to fire APIs | ✅ `neutralizeVueRouter` + native redirect neutralization |
| React route capture | supplement routes | ⚠️ static + clicking; no dedicated hook |
| Navigation blocking (login path) | stay on page for analysis | ⚠️ block only the login path — don't obstruct business navigation |
| Hook crypto libs (CryptoJS/SM etc.) | encrypted params → plaintext API body | ❌ manually hook the encrypt fn's inputs; record findings in config |
| Anti-debug bypass | otherwise runtime records no APIs | ❌ handle manually; static still works |

---

## E. Endpoint-extraction regexes (when static yields too few)

Loosen `extract_endpoints` in `harvest_static.py`, or run manually:

```bash
grep -rhoaE '"/[a-z][A-Za-z0-9_/\-]{3,}"' js | sort -u
grep -rhoaE '/api/[a-zA-Z0-9_./-]+' js | sort -u
```

---

## F. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| Too few static APIs | endpoint dialect mismatch → loosen regexes (section D) |
| chunk count ≪ manifest | CSS-only or undeployed chunks; 404s already retried |
| runtime still shows login | render gate wrong → recheck A1: key name, container, encoding, domain |
| inside shell but modules blank | content gate → forge menus (A3); `routes` paths may be wrong |
| only bootstrap/locale per route | incomplete permission codes → section I tree restoration; check the `role_permissions` + `permissions/all` dual stub |
| sidebar has items but subpages blank | tree missing intermediate nodes, or codes don't match `userRouteAuth` |
| every API redirects to login | interceptor gate → confirm `neutralize`; nested fields need extended walk logic |
| 0 WS frames | subscribe only fires after user interaction; increase `perRouteMs` |
| empty response bodies | real responses only with `forward: true` |
| Chromium missing | install chromium or set `config.chromium` / `CHROMIUM` |
| many mocks yet still at login | hook too late or missing `location.href` setter → document-start + preload |
| all lists empty | L3 empty arrays are normal; keep clicking tabs/settings/details |
| Redux actions mistaken for routes | filter internal paths containing get/set/change/clear/toggle/upload |
| Vue still redirects to login | preload not at document-start → fix injection timing; or manually clear guards when `neutralizeVueRouter: false` |
| URLs in responses not logged | enable `extractUrlsFromResponse`; or extract manually from `__API_RECON_DETAIL__` |
| unknown Authorization header name | enable `observe.xhrHeaders` or check request headers in DevTools |
| runtime very slow / timeouts | set `waitUntil: domcontentloaded`; lower `routeTimeout`; avoid `networkidle2` |
| proxy connection fails | check `proxy` / env vars; keep Puppeteer and curl proxy ports consistent |

---

## G. Hardened targets

When the server progressively validates the session (signed cookies that can't be forged, server-rendered menus that can't be stubbed), runtime stalls at the shell. Expected behavior:

- **static alone suffices for endpoint enumeration** — module paths live in the code
- if authorization permits, run the same harness with a **real session**: `forward: true`, no neutralize needed — capture real methods/params/responses

---

## H. Per-task checklist

1. Confirm the authorization scope
2. **Read** `scripts/harvest_static.py` → adapt to the target → run → review `api_static.txt`, `routes.txt`
3. **Phase 1b**: path anchor-window expansion + binding layers → `param_candidates.json` (section J)
4. Reverse A1/A2/A3 → write a site-specific `config.json`
5. **Read and adapt** `runtime_harvest.js` / `preload.js` before running
6. `runtimeMode=depth`: `npm install` → run the adapted harvest script
7. `runtimeMode=coverage/both`: document-start inject the adapted preload → browser MCP dynamic enumeration + **parameter trigger matrix**
8. Modules don't render → **section I tree restoration** → patch stubs → re-run
9. Multi-sample param diff + error inference → `params_merged.json`
10. Merge → `site_map.json` + `api_merged.txt`; honestly annotate coverage, gaps, and script changes

---

## I. Permission-tree restoration (Phase 4 deep dive)

Use when a simple forged `menus: [{ path, show: true }]` fails and submodules still won't mount.

### I1. Locate the auth module

```bash
grep -l 'userRouteAuth' js/*.js
grep -l 'routeMap\|routeLink' js/*.js
grep -rhoaE 'getResultTree|role_permissions|permissions/all' js | head
```

Record: **permission API path**, **response field names**, **consumer chunk filename**.

### I2. Extract routeMap

```bash
python3 scripts/extract_route_map.py recon/js recon/
# produces recon/route_map.json
```

If `[!] no routeMap pattern found`: loosen the regex in `extract_route_map.py`, or grep manually:

```bash
grep -rhoaE '([A-Z_][A-Z0-9_]*):\{name:"[^"]*",link:"/[^"]+"\}' js | head -20
```

### I3. Build the permission tree + stubs

```bash
python3 scripts/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Script logic:
1. Parse `userRouteAuth={MONITOR:{url:...},...}` (including webpack aliases like `He=o.DASHBOARD`)
2. Resolve aliases → real paths via `route_map.json`
3. Infer parents from code prefixes (`MONITOR_ALERT` → `MONITOR`)
4. Output `permissions_tree.json`, `permissions_all_stub.json`, `role_permissions_stub.json`
5. With `--config`, auto-write `stubs` and extended `routes` into `config.json`

**Adapt per target** (top of the script):
- `DEFAULT_ROOTS`: top-level module code list
- `DEFAULT_PREFIX_PARENT`: `PREFIX_` → parent mapping
- `DEFAULT_EXTRA_PARENT`: orphan nodes without a prefix relationship

### I4. Validate stub consistency

```bash
# permission count should ≈ userRouteAuth entry count
wc -l recon/perm_codes_all.txt
# routes should cover every link in route_map
python3 -c "import json; m=json.load(open('recon/route_map.json')); r=set(json.load(open('recon/config.json'))['routes']); print('missing', [v['link'] for v in m.values() if v['link'] not in r])"
```

### I5. Re-run runtime and compare

```bash
node recon/runtime_harvest.js recon/config.json
# compare runtime_api.json counts before/after forging; check whether module APIs like /attack, /asset appear
```

| Before forge | After forge (success) |
|---|---|
| same 3–5 bootstrap calls per route | different routes trigger different module APIs |
| only `/api/locale/language` | `/api/web/...` module endpoints appear |
| single-digit routes in `routes.txt` | `routes` 80–110+ from route_map |

### I6. If it still fails

- **coverage mode**: click sidebar + tabs — permission gating may only fire after interaction
- **stub fields**: compare real API responses (curl + real session) against the stub's nesting
- **extra guards**: grep `hasPermission|checkRole|func.` and other button-level checks; extend `role_permissions.permissions`
- **static fallback**: module API paths still live in `api_static.txt`; runtime only supplements METHOD/body — keep `param_candidates.json` + recorded samples for params

---

## J. Parameter reversing (Phase 1b / 5b / 5c)

**A methodology, not a turnkey script.** Find paths with regexes; find parameters via anchor-window expansion + UI binding chains + multi-sample diff + error inference.

### J1. Anchor-window expansion — from path to payload-assembly object

```bash
# anchor on paths known from Phase 1
grep -n '"/api/user/list"' js/*.js
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' js | head
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' js | head
grep -rhoaE '(get|post|put|delete|patch)\([^,]+,\s*\{' js | head
```

### J2. Wrapper layers and transport shapes

```bash
# axios / unified request
grep -rhoaE '(axios|request)\.(get|post|put|delete|patch)\(' js | head
grep -rhoaE 'interceptors\.(request|response)' js | head

# GraphQL
grep -rhoaE '(query|mutation)\s+\w+|gql`|graphql\(' js | head
grep -rhoaE '\$[a-zA-Z_]+\s*:\s*(Int|String|Boolean|\[)' js | head

# FormData / multipart
grep -rhoaE 'FormData|\.append\(' js | head

# path params
grep -rhoaE 'path:\s*"/[^"]*:[^"]+"' js | head
grep -rhoaE 'useParams|route\.params|\$route\.params' js | head
```

### J3. Validation gates — required / format / enum

```bash
grep -rhoaE '(required|message|pattern|enum|validator)\s*:' js | head
grep -rhoaE 'yup\.|zod\.|async-validator|Form\.Item|a-form-item|el-form-item' js | head
grep -rhoaE 'rules\s*:\s*\[|name:\s*["\'][a-zA-Z_]+["\']' js | head
grep -rhoaE 'label.*value|options\s*:\s*\[' js | head
```

### J4. Binding layer — form → API

```bash
grep -rhoaE 'onFinish|handleSubmit|getFieldsValue|validateFields' js | head
grep -rhoaE '(pick|omit|transform|dayjs|moment)\(' js | head
```

Runtime assist: DevTools → Network → request → **Initiator** (call stack) — trace upward from `fetch`/`send` to the payload-assembly function.

### J5. Encrypted parameters

```bash
grep -rhoaE 'encrypt|decrypt|sign|CryptoJS|sm2|sm3|sm4|RSA|AES' js | head
```

**Never guess fields on ciphertext** — hook the encryption function's **inputs** and record the plaintext payload pre-encryption; write findings into `config.json` / `param_candidates.json`.

### J6. Parameter trigger matrix (mandatory in Phase 3)

For each module, record once per operation and diff request body/query:

| Operation | Watch for |
|---|---|
| list first paint | pagination defaults |
| search | keyword, filters |
| advanced filter | optional fields |
| create/edit | full entity |
| bulk/export | `ids[]`, `exportType` |
| sort/page | `sortField`, `order` |

Produce `param_samples.json`: `[{ "path", "method", "action": "search", "body", "query", "headers" }]`

### J7. Confidence rules

| Confidence | Condition |
|---|---|
| **high** | static callsite + ≥2 consistent runtime samples |
| **medium** | static only, or a single runtime sample |
| **low** | inferred from response/error, not re-verified |
| **pending** | field known statically, UI/permissions not yet exercised |

### J8. Scenario quick-map

| Scenario | Sequence |
|---|---|
| REST list page | J1 payload object → J6 four-way diff → J3 rules |
| create/edit form | J3 Form name → J4 submit chain → runtime submit + leave fields blank to read 400s |
| GraphQL | J2 variables declarations → record variables per operation at runtime |
| encrypted body | J5 hook inputs → pre-encryption fields are the real params |

### J9. Mapping to api-recon phases

| api-recon | param recon |
|---|---|
| Phase 1 static | J1 anchor-window expansion |
| Phase 2 A2 interceptor | globally injected fields (tenantId, sign) |
| Phase 3 runtime | J6 trigger matrix + `param_samples.json` |
| Phase 4 permission tree | different modules → different forms → full fields only with sufficient permissions |
| Phase 5 merge | `params_merged.json` + confidence; never decide requiredness from one sample |

### J10. Troubleshooting

| Symptom | Fix |
|---|---|
| field seen statically never appears at runtime | mark "pending"; restore the perm tree / click advanced filters / exercise every select option |
| same path, different body shapes | normal — record separately per `action`; don't force-merge schemas |
| stub responses are fake but you want params | **inspect outbound request** body/headers — never infer from stub responses |
| 400 mentions a nested field | watch outer wrappers like `data`/`bizData`/`variables` |
| GraphQL shows only operation names | expand the `variables` JSON; find `$var: Type` statically |

---
