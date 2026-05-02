The code facts check out. Let me verify the exact lines:

- `rest/server.js` line 58: `app.set('trust proxy', true)` — **confirmed** [1](#0-0) 
- `rest/middleware/responseHandler.js` line 57: `logger.info(`${req.ip} ...`)` — **confirmed** [2](#0-1) 

SECURITY.md exclusions reviewed — none cover log-source IP spoofing (the closest candidates, "best practice recommendations" and "server-side non-confidential information disclosure, such as IPs," do not apply: the former is too generic for a concrete misconfiguration with a demonstrable exploit, and the latter concerns *disclosing* server IPs to clients, not *forging* client IPs in server logs). [3](#0-2) 

---

# Audit Report

## Title
Log Source IP Spoofing via Unvalidated `X-Forwarded-For` Header in `responseHandler`

## Summary
`rest/server.js` sets `app.set('trust proxy', true)`, causing Express to resolve `req.ip` to the leftmost (attacker-controlled) value of any `X-Forwarded-For` header. `rest/middleware/responseHandler.js` logs this value verbatim, allowing any unauthenticated client to forge the source IP recorded in every access log entry.

## Finding Description
**Root cause chain:**

1. `rest/server.js` line 58 sets `app.set('trust proxy', true)`. [4](#0-3) 
   Express's boolean `true` value for `trust proxy` instructs the framework to trust **all** hops in `X-Forwarded-For` unconditionally and resolve `req.ip` to the **leftmost** entry — regardless of whether the request actually traversed a trusted proxy. Express explicitly documents that `true` should not be used when the server is directly reachable from the internet, recommending a specific IP, CIDR, or hop count instead.

2. `rest/middleware/responseHandler.js` line 57 logs `req.ip` verbatim with no sanitisation or validation: [2](#0-1) 
   The value flows directly from the untrusted header into the log sink.

## Impact Explanation
Security analysts responding to incidents (abuse, scraping, API attacks) will investigate a forged IP address. The real attacker's TCP source address is never recorded. This directly undermines forensic integrity and any SIEM/alerting logic that correlates events by source IP. Severity: **Medium** — no data exfiltration or privilege escalation, but it actively degrades every detective control that depends on source-IP attribution.

## Likelihood Explanation
Exploitation requires zero privileges, zero authentication, and a single HTTP request with a crafted `X-Forwarded-For` header. The technique is universally known, trivially scriptable, and repeatable at will from any internet client. Likelihood: **High**.

## Recommendation
Replace the blanket `trust proxy: true` with a restrictive value scoped to the actual trusted reverse-proxy infrastructure, for example:

```js
// Trust only the immediately adjacent proxy (1 hop)
app.set('trust proxy', 1);

// Or trust a specific CIDR range of known load-balancers
app.set('trust proxy', '10.0.0.0/8');
```

This ensures `req.ip` reflects the real client IP as seen by the trusted proxy, rather than an arbitrary header value supplied by the client.

## Proof of Concept
```
GET /api/v1/transactions HTTP/1.1
Host: <mirror-node>
X-Forwarded-For: 192.168.1.1
```

With `trust proxy: true`, Express sets `req.ip = "192.168.1.1"`. The resulting log line emitted at `responseHandler.js:57` becomes:

```
INFO 192.168.1.1 GET /api/v1/transactions in 12 ms: 200
```

The attacker's real TCP source IP is absent from all logs.

### Citations

**File:** rest/server.js (L57-59)
```javascript
app.disable('x-powered-by');
app.set('trust proxy', true);
app.set('port', port);
```

**File:** rest/middleware/responseHandler.js (L56-58)
```javascript
  if (code >= 400 || Math.random() <= sampleRate) {
    logger.info(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${code}`);
  }
```

**File:** SECURITY.md (L15-16)
```markdown
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.
```
