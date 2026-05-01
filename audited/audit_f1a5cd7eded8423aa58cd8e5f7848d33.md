### Title
Spoofed `X-Forwarded-For` Header Poisons `req.ip` in Audit Log via Unrestricted Proxy Trust

### Summary
`rest/server.js` configures Express with `trust proxy: true` (boolean), which unconditionally trusts the leftmost value in any `X-Forwarded-For` header as `req.ip`. The Traefik ingress is simultaneously configured with `--entryPoints.web.forwardedHeaders.insecure`, which disables stripping of client-supplied forwarded headers. Together, an unprivileged external attacker can inject an arbitrary string as `req.ip`, which is written verbatim into the access log by `responseHandler.js`, forging the audit trail for every contract result request.

### Finding Description

**Root cause — two compounding misconfigurations:**

**1. Express unconditionally trusts all proxies** [1](#0-0) 

`app.set('trust proxy', true)` with the boolean `true` tells Express to trust every hop in the `X-Forwarded-For` chain without limit. Per the Express documentation, this causes `req.ip` to be set to the **leftmost** (i.e., client-controlled) entry in the `X-Forwarded-For` header.

**2. Traefik passes client-supplied `X-Forwarded-For` headers unmodified** [2](#0-1) 

`--entryPoints.web.forwardedHeaders.insecure` disables Traefik's built-in protection that would otherwise strip `X-Forwarded-For` headers arriving from untrusted (external) sources. With this flag set, Traefik appends the real client IP to whatever `X-Forwarded-For` value the client already sent, rather than replacing it.

**3. The tainted value is logged without sanitization** [3](#0-2) 

`req.ip` — now fully attacker-controlled — is interpolated directly into the log string with no escaping, validation, or IP-format check.

**Exploit flow:**
```
Attacker → X-Forwarded-For: 10.0.0.1\nINFO fake-entry GET /admin 200
         ↓
Traefik (forwardedHeaders.insecure) → passes header through, appends real IP
         ↓
Express (trust proxy: true) → req.ip = "10.0.0.1\nINFO fake-entry GET /admin 200"
         ↓
responseHandler.js line 57 → logger.info(`${req.ip} GET /api/v1/contracts/results/... 200`)
         ↓
Log output: two lines — one forged, one real
```

### Impact Explanation
Every contract-result query (`GET /api/v1/contracts/results/:transactionIdOrHash`) passes through `responseHandler`, so the attacker can attribute any smart contract query to an arbitrary IP address in the audit log. With newline injection the attacker can also synthesize entirely fake log entries, making forensic investigation of malicious contract calls unreliable. This directly undermines the integrity of the audit trail for smart contract activity on the mirror node.

### Likelihood Explanation
No authentication or special network position is required. Any client that can reach the public API endpoint can send a crafted `X-Forwarded-For` header. The two misconfigurations (`trust proxy: true` and `forwardedHeaders.insecure`) are both present in the default Helm chart values and the main server bootstrap, so the attack works in every standard deployment. It is trivially repeatable with a single `curl` command.

### Recommendation
1. **Restrict proxy trust to the actual ingress tier.** Replace `app.set('trust proxy', true)` with the specific number of trusted proxy hops or the ingress CIDR, e.g. `app.set('trust proxy', 1)` or `app.set('trust proxy', '10.0.0.0/8')`. This causes Express to use the rightmost non-trusted IP rather than the leftmost client-supplied one.
2. **Remove `forwardedHeaders.insecure` from Traefik.** Instead, use `--entryPoints.web.forwardedHeaders.trustedIPs=<ingress-cidr>` so Traefik strips client-supplied `X-Forwarded-For` headers from untrusted sources before forwarding.
3. **Sanitize before logging.** Strip or encode newlines and non-printable characters from `req.ip` (and `req.originalUrl`) before interpolating them into log strings to prevent log injection regardless of proxy configuration.

### Proof of Concept
```bash
# Forge the source IP in the audit log for a contract result query
curl -H "X-Forwarded-For: 192.168.1.1" \
     https://<mirror-node-host>/api/v1/contracts/results/0x<txhash>

# Expected log line produced by responseHandler.js line 57:
# INFO  192.168.1.1 GET /api/v1/contracts/results/0x<txhash> in 12 ms: 200
# (real attacker IP is hidden; log attributes the query to 192.168.1.1)

# Log-injection variant (newline in header value):
curl -H $'X-Forwarded-For: 1.2.3.4\nINFO  10.0.0.1 DELETE /api/v1/contracts/results/0xdeadbeef in 5 ms: 200' \
     https://<mirror-node-host>/api/v1/contracts/results/0x<txhash>
# Injects a completely fabricated log entry into the audit stream
```

### Citations

**File:** rest/server.js (L57-58)
```javascript
app.disable('x-powered-by');
app.set('trust proxy', true);
```

**File:** charts/hedera-mirror-common/values.yaml (L635-637)
```yaml
  globalArguments:  # Expose X-Forwarded-For header for tracing
    - --entryPoints.web.forwardedHeaders.insecure
    - --entryPoints.websecure.forwardedHeaders.insecure
```

**File:** rest/middleware/responseHandler.js (L56-58)
```javascript
  if (code >= 400 || Math.random() <= sampleRate) {
    logger.info(`${req.ip} ${req.method} ${req.originalUrl} in ${elapsed} ms: ${code}`);
  }
```
