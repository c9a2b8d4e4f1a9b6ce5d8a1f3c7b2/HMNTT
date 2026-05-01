### Title
Host Header Injection in `getPaginationLink()` Enables Open Redirect / SSRF via Pagination `next` Link

### Summary
When `config.response.includeHostInLink` is set to `true`, `getPaginationLink()` in `rest/utils.js` constructs the `next` pagination URL using `req.hostname` without any validation or sanitization. Because the server sets `trust proxy: true` globally, Express derives `req.hostname` from the attacker-controlled `X-Forwarded-Host` (or `Host`) header, allowing any unauthenticated user to inject an arbitrary hostname into the returned `next` link.

### Finding Description

**Exact code path:**

`rest/controllers/tokenController.js` line 83 calls `utils.getPaginationLink(req, false, lastValue, query.order)`.

`rest/utils.js` lines 805–818:
```js
const getPaginationLink = (req, isEnd, lastValueMap, order) => {
  if (isEnd) { return null; }
  const urlPrefix = config.response.includeHostInLink
    ? `${req.protocol}://${req.hostname}:${config.port}`
    : '';
  ...
  return urlPrefix + req.baseUrl + path + nextParamQueries;
};
```

`rest/server.js` line 58:
```js
app.set('trust proxy', true);
```

**Root cause:** When `includeHostInLink` is `true`, the URL prefix is assembled directly from `req.hostname`. In Express, with `trust proxy: true`, `req.hostname` is populated from the `X-Forwarded-Host` header first, then the `Host` header — both of which are fully attacker-controlled. There is no allowlist, regex validation, or comparison against a configured canonical hostname anywhere in the code path.

**Failed assumption:** The code assumes `req.hostname` reflects the legitimate server hostname. With `trust proxy: true` and no reverse-proxy that strips/overwrites `X-Forwarded-Host`, this assumption is false for any external request.

### Impact Explanation

- **Open Redirect:** Any API consumer that automatically follows the `next` link (SDK, crawler, aggregator) is redirected to the attacker's host.
- **SSRF:** If any internal service or middleware follows the generated `next` link server-side, it will issue a request to the attacker-controlled host, potentially leaking internal tokens, timing data, or enabling further pivoting.
- **Cache Poisoning:** If the response containing the poisoned `next` link is cached (the codebase has a Redis response cache), the malicious link is served to all subsequent users who receive the cached response.
- Severity: **Medium–High** when `includeHostInLink=true` is deployed (e.g., behind a load balancer that does not sanitize `X-Forwarded-Host`).

### Likelihood Explanation

- **Precondition:** `config.response.includeHostInLink` must be `true`. This is non-default (`false` by default per `rest/__tests__/config.test.js` line 53), but the configuration docs list it as a supported option and operators may enable it for absolute URL generation.
- **Attacker capability:** Zero privilege required. Any HTTP client can set the `Host` or `X-Forwarded-Host` header.
- **Repeatability:** 100% reproducible; no race condition or timing dependency.
- **Real-world deployments:** Cloud/Kubernetes deployments commonly set `includeHostInLink: true` to generate fully-qualified pagination links. Many ingress controllers pass `X-Forwarded-Host` through without stripping it.

### Recommendation

1. **Validate `req.hostname` against a configured allowlist** before using it in URL construction:
   ```js
   const allowedHosts = config.response.allowedHosts; // e.g., ['mirrornode.example.com']
   const hostname = allowedHosts.includes(req.hostname) ? req.hostname : config.response.defaultHost;
   const urlPrefix = config.response.includeHostInLink
     ? `${req.protocol}://${hostname}:${config.port}`
     : '';
   ```
2. **Alternatively, use a static configured hostname** (`config.response.host`) instead of `req.hostname` entirely when building the prefix, eliminating the dependency on the request header.
3. **If a reverse proxy is in front**, configure it to explicitly set and overwrite `X-Forwarded-Host` to the canonical hostname before requests reach the Node.js process.

### Proof of Concept

**Precondition:** `hiero.mirror.rest.response.includeHostInLink: true` is set in the deployment config.

**Steps:**

1. Send a request to the token relationships endpoint with a spoofed host header:
   ```
   GET /api/v1/accounts/0.0.1234/tokens?limit=1 HTTP/1.1
   Host: legitimate-mirror.example.com
   X-Forwarded-Host: attacker.com
   ```

2. The server processes the request. `req.hostname` resolves to `attacker.com` (Express with `trust proxy: true` prefers `X-Forwarded-Host`).

3. `getTokenRelationships` calls `utils.getPaginationLink(req, false, {token.id: '0.0.5000'}, 'asc')`.

4. `getPaginationLink` constructs:
   ```
   urlPrefix = "http://attacker.com:5551"
   ```
   and returns:
   ```
   "http://attacker.com:5551/api/v1/accounts/0.0.1234/tokens?limit=1&token.id=gt:0.0.5000"
   ```

5. The JSON response body contains:
   ```json
   {
     "tokens": [...],
     "links": {
       "next": "http://attacker.com:5551/api/v1/accounts/0.0.1234/tokens?limit=1&token.id=gt:0.0.5000"
     }
   }
   ```

6. Any client following the `next` link connects to `attacker.com` instead of the legitimate mirror node. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/utils.js (L805-819)
```javascript
const getPaginationLink = (req, isEnd, lastValueMap, order) => {
  if (isEnd) {
    return null;
  }

  const urlPrefix = config.response.includeHostInLink ? `${req.protocol}://${req.hostname}:${config.port}` : '';
  const nextParamQueries = getNextParamQueries(order, req.query, lastValueMap);
  if (nextParamQueries === null) {
    return null;
  }

  // remove the '/' at the end of req.path
  const path = req.path.endsWith('/') ? req.path.slice(0, -1) : req.path;
  return urlPrefix + req.baseUrl + path + nextParamQueries;
};
```

**File:** rest/server.js (L58-58)
```javascript
app.set('trust proxy', true);
```

**File:** rest/controllers/tokenController.js (L77-84)
```javascript
    let nextLink = null;
    if (tokens.length === query.limit) {
      const lastRow = last(tokens);
      const lastValue = {
        [filterKeys.TOKEN_ID]: lastRow.token_id,
      };
      nextLink = utils.getPaginationLink(req, false, lastValue, query.order);
    }
```

**File:** rest/__tests__/config.test.js (L53-53)
```javascript
  expect(actual.rest.response.includeHostInLink).toBe(false);
```
