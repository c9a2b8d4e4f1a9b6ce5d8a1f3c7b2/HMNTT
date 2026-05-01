### Title
Unbounded Attacker-Controlled Path Logged at INFO Level Enables Disk-Exhaustion DoS in `TracingMiddleware`

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` unconditionally logs the full `request.URL.RequestURI()` value and the attacker-controlled `X-Forwarded-For`/`X-Real-IP` header at `log.Info` level for every non-internal-path request, with no length truncation or application-level rate limiting. An unauthenticated attacker can flood the server with requests carrying near-maximum-length URLs and spoofed IP headers, causing the log subsystem to write up to ~1 MB per request to disk, exhausting filesystem space and causing a denial of service.

### Finding Description
**Exact code path:**

- `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61
- Line 47: `path := request.URL.RequestURI()` — the full URI (path + query string) is captured with no length check.
- Lines 63–74: `getClientIpAddress()` reads `X-Real-IP` then `X-Forwarded-For` headers verbatim, also with no length check.
- Lines 52–53: both values are embedded directly into `message` via `fmt.Sprintf`.
- Lines 55–58: if `path` is not in `internalPaths` (liveness, readiness, metrics), `log.Info(message)` is called — the default branch for every API request.

**Root cause:** The middleware makes the failed assumption that logged request metadata is bounded in size. Neither `path` nor `clientIpAddress` is truncated before being written to the log.

**Exploit flow:**
1. Attacker sends HTTP requests to any non-internal endpoint (e.g., `GET /network/list?<8000-byte junk>`).
2. Go's `net/http` server accepts request lines up to `MaxHeaderBytes` (default 1 MB, not overridden in `rosetta/main.go` lines 220–227).
3. `TracingMiddleware` constructs a ~1 MB log message and calls `log.Info`, writing it to disk.
4. Attacker repeats in a tight loop from multiple source IPs.

**Why existing checks fail:**
- The `internalPaths` map check (line 55) only switches between `log.Debug` and `log.Info`; it performs no length validation.
- The Traefik `rateLimit` (`average: 10` per `requestHost`) in `charts/hedera-mirror-rosetta/values.yaml` lines 157–160 is: (a) optional — only applied when `global.middleware` and `middleware` Helm values are set; (b) per-`requestHost`, trivially bypassed by varying the `Host` header; (c) entirely absent at the application layer.
- No `http.Server.MaxHeaderBytes` override is set in `rosetta/main.go`, so the default 1 MB cap is the only bound.

### Impact Explanation
A sustained flood of requests with maximum-length URLs fills the log partition. Once the filesystem is full, the process cannot write logs, and depending on OS behavior, may also fail to write other files (temp files, DB WAL, etc.), causing the Rosetta node to crash or become unresponsive. This is a non-network-based DoS (disk exhaustion) that requires no authentication and no valid API payload.

### Likelihood Explanation
Any unprivileged external user who can reach the Rosetta HTTP port can trigger this. No credentials, API keys, or special protocol knowledge are required — a simple HTTP GET with a long query string suffices. The attack is trivially scriptable (`curl`, `ab`, `wrk`) and repeatable. Deployments that expose the port directly (without Traefik, or with `global.middleware: false`) have zero application-level mitigation.

### Recommendation
1. **Truncate before logging:** Cap `path` and `clientIpAddress` to a safe maximum (e.g., 512 bytes) before constructing the log message:
   ```go
   const maxLogFieldLen = 512
   if len(path) > maxLogFieldLen {
       path = path[:maxLogFieldLen] + "…"
   }
   ```
2. **Apply rate limiting at the application layer** (e.g., `golang.org/x/time/rate` per-IP token bucket) so it is always enforced regardless of deployment topology.
3. **Set `MaxHeaderBytes`** explicitly on the `http.Server` to a value appropriate for the API (e.g., 8 KB) to reduce the maximum per-request log payload.
4. **Use structured logging** with fixed-width fields so oversized values are rejected at the schema level.

### Proof of Concept
```bash
# Generate a ~8000-byte query string
LONG_PATH="/network/list?$(python3 -c 'print("A"*8000)')"

# Flood the server (no auth required)
for i in $(seq 1 100000); do
  curl -s -o /dev/null \
    -H "X-Forwarded-For: $(python3 -c 'print("1.2.3.4,"*200)')" \
    "http://<rosetta-host>:8082${LONG_PATH}" &
done
wait
```
Each request causes `TracingMiddleware` to call `log.Info` with a message containing the full ~8 KB path and ~800-byte spoofed IP string. At 100 000 requests, this writes ~900 MB to the log partition. Scaling to millions of requests exhausts typical disk allocations.