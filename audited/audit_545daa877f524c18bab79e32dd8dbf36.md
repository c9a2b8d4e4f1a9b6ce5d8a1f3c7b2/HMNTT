### Title
IP Spoofing via `X-Forwarded-For` Header Defeats Audit Log Correlation in `responseHandler`

### Summary
The Express application unconditionally trusts all proxy headers (`app.set('trust proxy', true)`) with no restriction on which upstream sources are trusted. Because `req.ip` is derived from the attacker-controlled `X-Forwarded-For` header, any unprivileged external client can inject an arbitrary IP address into the access log line emitted by `responseHandler`, completely defeating IP-based audit correlation for Hashgraph history queries.

### Finding Description
**Root cause — `rest/server.js` line 58:**

```js
app.set('trust proxy', true);
``` [1](#0-0) 

When Express's `trust proxy` is set to the boolean `true`, it trusts **every** hop in the `X-Forwarded-For` chain unconditionally, regardless of whether the request actually came through a trusted reverse proxy. Express then sets `req.ip` to the **leftmost** (client-supplied) value in that header.

**Sink — `rest/middleware/responseHandler.js` line 57:**

```js
logger.info(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${code}`);
``` [2](#0-1) 

`req.ip` is logged verbatim with no sanitisation or validation. Because `trust proxy: true` makes `req.ip` reflect the attacker-supplied header value, the logged IP is fully attacker-controlled.

**Exploit flow:**
1. Attacker sends a direct HTTP request to the mirror-node REST API with a crafted header:
   ```
   GET /api/v1/transactions HTTP/1.1
   Host: mirror.example.com
   X-Forwarded-For: 192.0.2.1
   ```
2. Express reads `X-Forwarded-For`, trusts it unconditionally, and sets `req.ip = "192.0.2.1"`.
3. `responseHandler` logs: `192.0.2.1 GET /api/v1/transactions in 12 ms: 200`.
4. The attacker's real IP never appears in the audit log.

**Existing checks — none sufficient:**
There is no middleware that validates whether the request actually arrived from a known/trusted proxy before accepting the `X-Forwarded-For` value. The `authHandler` and `requestLogger` middlewares run before `responseHandler` but neither normalises or rejects spoofed forwarding headers. [3](#0-2) 

The same misconfiguration is present in the monitoring server: [4](#0-3) 

### Impact Explanation
An attacker querying Hashgraph history (transactions, account balances, NFT ownership, topic messages, etc.) can attribute every one of their requests to an arbitrary IP address — including a legitimate user's IP — in the audit log. This breaks IP-based rate-limit enforcement, incident response, and forensic attribution. In regulated environments where the mirror node access log is used as an audit trail for ledger history access, this constitutes a direct integrity failure of that trail.

### Likelihood Explanation
No authentication, special tooling, or network position is required. Any HTTP client capable of setting a custom header (curl, browser, scripted bot) can exploit this. The attack is trivially repeatable, leaves no trace of the real source IP, and requires zero privileges.

### Recommendation
Replace the blanket `true` with the number of trusted proxy hops or an explicit list of trusted proxy IP ranges:

```js
// Trust exactly one hop (the load balancer / ingress)
app.set('trust proxy', 1);

// Or trust only specific CIDR ranges
app.set('trust proxy', '10.0.0.0/8, 172.16.0.0/12');
```

With `trust proxy` set to a hop count or IP allowlist, Express will only accept `X-Forwarded-For` values prepended by a verified trusted proxy, and will fall back to the TCP socket address (`req.socket.remoteAddress`) for direct connections, making `req.ip` non-spoofable by external clients. [1](#0-0) 

### Proof of Concept
```bash
# Spoof source IP as 1.2.3.4 while querying Hashgraph transaction history
curl -H "X-Forwarded-For: 1.2.3.4" \
     http://<mirror-node-host>/api/v1/transactions

# Resulting log line (attacker's real IP is absent):
# 1.2.3.4 GET /api/v1/transactions in 8 ms: 200
```

### Citations

**File:** rest/server.js (L57-59)
```javascript
app.disable('x-powered-by');
app.set('trust proxy', true);
app.set('port', port);
```

**File:** rest/server.js (L82-87)
```javascript
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

```

**File:** rest/middleware/responseHandler.js (L56-58)
```javascript
  if (code >= 400 || Math.random() <= sampleRate) {
    logger.info(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${code}`);
  }
```

**File:** rest/monitoring/server.js (L21-22)
```javascript
app.set('trust proxy', true);
app.set('port', port);
```
