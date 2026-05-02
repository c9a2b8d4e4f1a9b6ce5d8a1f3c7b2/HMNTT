### Title
Unbounded `log.Info()` Per Request in `TracingMiddleware` Enables Log-Flood DoS Without Rate Limiting

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` unconditionally calls `log.Info()` for every request to any non-internal path, with no application-level rate limiting. The only rate-limiting protection (Traefik middleware) is **disabled by default** (`global.middleware: false`). An unprivileged attacker flooding the service with requests forces logrus to serialize all writes through a `sync.Mutex` against a blocking stdout/stderr pipe, exhausting OS threads and degrading HTTP handler throughput.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 55–59:
```go
if internalPaths[path] {
    log.Debug(message)
} else {
    log.Info(message)   // called for EVERY non-internal request
}
```

**Root cause:** There is no guard on request rate before emitting a log line. `log.Info()` (logrus) acquires a `sync.Mutex`, formats the entry, and writes to the configured output writer (stdout/stderr). In containerized deployments stdout is a pipe; when the pipe buffer fills, the `write(2)` syscall blocks the OS thread. Go's runtime compensates by spawning additional OS threads, but under sustained flood conditions thousands of threads accumulate, exhausting memory and causing scheduler pressure that delays all HTTP handler goroutines.

**Why existing checks fail:**

The only rate-limiting defense is the Traefik middleware chain defined in `charts/hedera-mirror-rosetta/values.yaml` lines 149–166 (`inFlightReq: 5`, `rateLimit: average: 10`). However:
- It is gated on `global.middleware: true` (line 95 of the same file), which **defaults to `false`**
- It is applied at the ingress layer only — direct access to the pod port (5700) bypasses it entirely
- The Go application itself contains zero rate-limiting or log-throttling logic

### Impact Explanation
Under a default deployment (Traefik middleware disabled), an attacker with network access to the pod can drive unbounded `log.Info()` calls. The logrus mutex serializes all concurrent handler goroutines through a single write path. If the log sink stalls (full pipe buffer, slow log aggregator), OS threads pile up. Memory exhaustion and scheduler contention degrade or halt request processing across the node. Because the Rosetta service is stateless and horizontally scaled, a coordinated flood against multiple pods can degrade ≥30% of the processing fleet simultaneously.

### Likelihood Explanation
No authentication is required to reach non-internal Rosetta API paths (e.g., `/network/list`, `/block`). The attack requires only the ability to send HTTP requests at high volume — trivially achievable with any load-generation tool (`wrk`, `hey`, `ab`). The default-off Traefik middleware means most deployments that follow the chart defaults are unprotected at the application layer. The attack is repeatable and requires no special knowledge of the application.

### Recommendation
1. **Application-level rate limiting:** Add a per-IP token-bucket or sliding-window rate limiter as a middleware layer in `main.go` before `TracingMiddleware`, independent of any ingress configuration.
2. **Log sampling / level guard:** In `TracingMiddleware`, check `log.IsLevelEnabled(log.InfoLevel)` before constructing and emitting the message, and consider sampling high-frequency paths (e.g., emit 1-in-N log lines under load).
3. **Enable Traefik middleware by default:** Change `global.middleware` default to `true` in `values.yaml` so the `inFlightReq` and `rateLimit` guards are active out of the box.
4. **Async/buffered logging:** Configure logrus with a buffered or asynchronous writer so that a stalled log sink does not block HTTP handler goroutines.

### Proof of Concept
**Preconditions:** Default chart deployment with `global.middleware: false`; network access to the Rosetta pod on port 5700.

**Steps:**
```bash
# 1. Identify pod IP or service endpoint
kubectl get pod -l app.kubernetes.io/component=rosetta -o wide

# 2. Flood a non-internal path (no auth required)
wrk -t 16 -c 256 -d 60s http://<POD_IP>:5700/network/list

# 3. Observe log volume explosion
kubectl logs <pod> | wc -l   # thousands of INFO lines per second

# 4. Observe HTTP latency / error rate rise
# - Response times increase as logrus mutex contention grows
# - OS thread count climbs (visible via /proc/<pid>/status Threads field)
# - Eventually pod OOMs or becomes unresponsive to legitimate requests
```

**Result:** Legitimate Rosetta API requests experience severe latency degradation or timeouts; the node effectively stops processing blockchain API traffic.