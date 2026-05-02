All key claims are verifiable in the actual code. Let me confirm each one before rendering a verdict.

**Code path confirmed** — `responseCacheCheckHandler()` at lines 63-73: when `clientCached === true`, only `delete headers[contentTypeHeader]` is executed; `negotiate()` is never called. [1](#0-0) 

**`negotiate()` is the sole setter of `Vary`** — line 122 is the only call to `res.setHeader(VARY_HEADER, ...)` in the file. [2](#0-1) 

**`vary` is stripped before storage** — `responseCacheUpdateHandler` explicitly deletes it at line 112, so `res.set(headers)` at line 75 cannot restore it. [3](#0-2) 

**Test explicitly asserts the missing header** — integration test line 211 confirms the current behavior is intentional/accepted. [4](#0-3) 

**SECURITY.md scope check** — The exclusion "Missing HTTP headers without demonstrated impact" (line 50) does not apply here because the claim provides a concrete impact chain. `Vary` is not a security header, so the line-39 exclusion also does not apply. [5](#0-4) 

---

Audit Report

## Title
Missing `Vary: Accept-Encoding` Header in 304 Cache-Hit Responses

## Summary
`responseCacheCheckHandler()` never calls `negotiate()` when serving a 304 (client-cached) response. Because `negotiate()` is the sole function that sets `Vary: accept-encoding`, and because `vary` is explicitly deleted from the stored headers before caching, the resulting 304 response carries no `Vary` header. This violates RFC 7234 §4.3.4 and can allow a compliant downstream cache to strip `Vary` from its stored entry, subsequently serving encoding-mismatched responses to all clients.

## Finding Description
In `rest/middleware/responseCacheHandler.js`, `responseCacheCheckHandler()`:

```
lines 63-73:
  if (isHead || clientCached) {
    if (clientCached) {
      delete headers[contentTypeHeader];   // only action taken; negotiate() skipped
    } else {
      negotiate(cachedResponse, req, res); // HEAD path calls negotiate
    }
  } else {
    const useCompressed = negotiate(cachedResponse, req, res); // normal GET calls negotiate
    ...
  }
``` [1](#0-0) 

`negotiate()` at line 122 is the **only** location that calls `res.setHeader(VARY_HEADER, 'accept-encoding')`. [6](#0-5) 

The `headers` object is built from `cachedResponse.headers`, which has `vary` explicitly deleted at line 112 of `responseCacheUpdateHandler` before storage. [7](#0-6) 

Therefore `res.set(headers)` at line 75 also cannot include `vary`. [8](#0-7) 

The behavior is confirmed by the integration test assertion:
```js
expect(response.headers).not.toHaveProperty('vary');
``` [9](#0-8) 

**RFC 7234 §4.3.4** states: *"The server generating a 304 response MUST generate any of the following header fields that would have been sent in a 200 (OK) response to the same request: … Vary."*

## Impact Explanation
A compliant CDN or reverse proxy (nginx, Varnish, Cloudflare, etc.) sitting in front of the mirror node:

1. Holds a cached 200 with `Vary: Accept-Encoding` and a gzip-encoded body.
2. Receives a conditional GET (`if-none-match: <valid-etag>`) from any client.
3. Forwards it to the origin; origin returns 304 **without** `Vary`.
4. Per RFC 7234 §4.3.4, the proxy updates its stored entry using the 304 headers, potentially removing `Vary: Accept-Encoding`.
5. The stored entry is now treated as encoding-agnostic; the proxy serves the gzip body to all subsequent clients regardless of their `Accept-Encoding`.
6. Clients without gzip support receive binary-encoded content instead of JSON, causing application-level failures for all users of that cached resource.

No data is leaked, but availability of API responses is degraded for all clients served by the poisoned cache entry.

## Likelihood Explanation
Preconditions are minimal:
- A valid ETag is obtainable by any unauthenticated GET to the same endpoint.
- The attack is a single HTTP request with two standard headers (`if-none-match`, `Accept-Encoding: gzip`).
- Any deployment with a CDN, load-balancer cache, or reverse proxy is potentially affected.
- The attack is repeatable after cache expiry.

The main limiting factor is that not all proxy implementations strictly follow RFC 7234 §4.3.4's header-replacement rule for absent headers; some only update headers that are explicitly present in the 304. This makes the attack CDN-implementation-dependent rather than universally exploitable, keeping severity at **Medium**.

## Recommendation
Call `negotiate()` (or at minimum call `res.setHeader(VARY_HEADER, 'accept-encoding')` directly) inside the `clientCached` branch of `responseCacheCheckHandler()`, so that 304 responses always include `Vary: accept-encoding` when the stored response would have included it. Update the integration test assertion at line 211 accordingly to assert the header IS present. [10](#0-9) 

## Proof of Concept
```
# Step 1 – obtain a valid ETag
curl -i https://<mirror-node>/api/v1/transactions?limit=1
# → 200 OK, Vary: accept-encoding, ETag: "abc123"

# Step 2 – trigger the poisoning request through the CDN
curl -i https://<mirror-node>/api/v1/transactions?limit=1 \
     -H 'if-none-match: "abc123"' \
     -H 'Accept-Encoding: gzip'
# → 304 Not Modified  (no Vary header in response)

# Step 3 – CDN updates stored entry, Vary removed

# Step 4 – subsequent client without gzip support receives garbled response
curl -i https://<mirror-node>/api/v1/transactions?limit=1
# → 200 from CDN cache, body is gzip-encoded binary, no Content-Encoding declared
```

### Citations

**File:** rest/middleware/responseCacheHandler.js (L63-73)
```javascript
  if (isHead || clientCached) {
    if (clientCached) {
      delete headers[contentTypeHeader];
    } else {
      // For HEAD requests when status code is not 304, negotiate the encoding and set corresponding headers
      negotiate(cachedResponse, req, res);
    }
  } else {
    const useCompressed = negotiate(cachedResponse, req, res);
    body = useCompressed ? cachedResponse.getBody() : cachedResponse.getUncompressedBody();
  }
```

**File:** rest/middleware/responseCacheHandler.js (L75-76)
```javascript
  res.set(headers);
  res.status(statusCode);
```

**File:** rest/middleware/responseCacheHandler.js (L108-112)
```javascript
      // Delete headers that will be re-computed when response later served by cache hit
      delete headers[CACHE_CONTROL_HEADER];
      delete headers[CONTENT_ENCODING_HEADER];
      delete headers[CONTENT_LENGTH_HEADER];
      delete headers[VARY_HEADER];
```

**File:** rest/middleware/responseCacheHandler.js (L121-135)
```javascript
const negotiate = (cachedResponse, req, res) => {
  res.setHeader(VARY_HEADER, 'accept-encoding');

  if (cachedResponse.compressed) {
    const negotiator = new Negotiator(req);
    if (negotiator.encoding([GZIP_ENCODING]) === GZIP_ENCODING) {
      res.setHeader(CONTENT_ENCODING_HEADER, GZIP_ENCODING);
      res.setHeader(CONTENT_LENGTH_HEADER, cachedResponse.getLength());
      return true;
    }
  }

  res.setHeader(CONTENT_LENGTH_HEADER, cachedResponse.getUncompressedLength());
  return false;
};
```

**File:** rest/__tests__/integration/responseCacheHandler.test.js (L205-211)
```javascript
    expect(response.statusCode).toEqual(304);
    expect(response.body).toBeEmpty();
    expect(response.get('etag')).toEqual(etag);
    expect(response.get('cache-control')).toMatch(/^public, max-age=\d+$/);
    expect(response.headers).not.toHaveProperty('content-encoding');
    expect(response.headers).not.toHaveProperty('content-length');
    expect(response.headers).not.toHaveProperty('vary');
```

**File:** SECURITY.md (L39-50)
```markdown
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
```
