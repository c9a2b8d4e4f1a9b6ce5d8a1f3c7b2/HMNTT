### Title
Unbounded URL Logged via `TracingMiddleware` — Query String Bypasses `internalPaths` Exact-Match, Enabling Log Flooding by Unprivileged Users

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` captures the full request URI (path + query string) via `request.URL.RequestURI()` and embeds it verbatim into a log message. The `internalPaths` map performs exact-string matching against bare paths (`/metrics`, `/health/liveness`, `/health/readiness`), so any request to `/metrics?<arbitrary-data>` fails the lookup and is logged at `Info` level with the full oversized URI. No URL length limit is enforced anywhere in the server configuration, allowing an unprivileged attacker to force arbitrarily large log writes per request.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 47–59:

```go
path := request.URL.RequestURI()          // line 47 — includes query string
// ...
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)  // line 52-53 — path embedded verbatim

if internalPaths[path] {                  // line 55 — exact map lookup
    log.Debug(message)
} else {
    log.Info(message)                     // line 58 — fires for /metrics?<huge>
}
```

`internalPaths` is defined at line 19:
```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
// keys: "/health/liveness", "/metrics", "/health/readiness"
```

**Root cause:** `request.URL.RequestURI()` returns the full URI including query string (e.g., `/metrics?a=AAAA…`). The map lookup compares this against bare path strings. Any query string — even a single character — causes a miss, routing execution to `log.Info` with the full, unsanitized, unbounded URI embedded in the message string.

The test in `trace_test.go` line 49 independently confirms this: `metricsPath + "s"` (i.e., `/metricss`) produces `levelInfo` output, demonstrating that any deviation from the exact key bypasses `log.Debug`.

**No server-side URL length limit:** `rosetta/main.go` lines 220–227 configure the `http.Server` with `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout`, but `MaxHeaderBytes` is never set. Go's default `http.DefaultMaxHeaderBytes` is 1 MB (1 << 20 bytes), which covers the request line including the URL. A 64 KB query string is well within this limit and is accepted without error. No middleware in the chain truncates or validates URL length before `TracingMiddleware` runs.

### Impact Explanation

Each request with a large query string causes:
- A heap allocation for the full URI string (up to ~1 MB per request)
- A `fmt.Sprintf` call building a message of equivalent size
- A synchronous `log.Info` write of that message to stdout/log sink

At modest request rates (e.g., 100 req/s with 64 KB URLs), this produces ~6.4 MB/s of log I/O and equivalent memory churn per second, with no per-request cost to the attacker beyond sending the HTTP request. Sustained over time this can exhaust disk space (log files), increase GC pressure, and degrade throughput for legitimate traffic. The `/metrics` endpoint is unauthenticated and publicly reachable by design.

### Likelihood Explanation

No authentication, API key, or rate limiting is visible in the codebase for the Rosetta HTTP server. Any network-reachable client can send a single HTTP GET with a large query string. The attack is stateless, trivially scriptable, and repeatable indefinitely. The attacker needs no credentials, no prior knowledge of the system beyond the port number, and no special tooling beyond `curl` or a basic HTTP client.

### Recommendation

1. **Strip query string before the `internalPaths` lookup** — use `request.URL.Path` instead of `request.URL.RequestURI()` for the map key, or parse and discard the query component before matching.
2. **Truncate the logged path** — cap the path string written to the log at a safe maximum (e.g., 512 bytes) before building `message`.
3. **Set `MaxHeaderBytes`** — explicitly set `http.Server.MaxHeaderBytes` to a small value (e.g., 8 KB) in `rosetta/main.go` to reject oversized request lines at the transport layer before they reach any middleware.
4. **Add rate limiting middleware** — apply a per-IP or global request rate limiter before `TracingMiddleware`.

### Proof of Concept

```bash
# Generate a 64 KB query string and send to the metrics endpoint
python3 -c "print('GET /metrics?a=' + 'A'*65536 + ' HTTP/1.1\r\nHost: target:5700\r\nConnection: close\r\n\r\n', end='')" \
  | nc <target-host> 5700

# Repeat in a loop to amplify log I/O
for i in $(seq 1 1000); do
  curl -s "http://<target-host>:5700/metrics?$(python3 -c "print('a='+'A'*65536)")" &
done
wait
```

Each iteration causes the server to allocate, format, and write a ~65 KB log line at `Info` level. Observe disk usage and stdout log volume growing proportionally. No credentials or special access required.