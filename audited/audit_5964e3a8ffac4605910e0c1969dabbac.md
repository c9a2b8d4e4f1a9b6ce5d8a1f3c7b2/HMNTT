### Title
Unbounded Idle Keep-Alive Connections Enable DoS Against `/construction/submit` (Transaction Gossip Blocking)

### Summary
The Rosetta API HTTP server in `rosetta/main.go` configures `IdleTimeout` from `Http.IdleTimeout` (default 10 seconds) but sets no upper bound on the number of concurrent connections. No application-level connection limiter (`netutil.LimitListener`, `ConnState` callback, or equivalent) is present anywhere in the Go codebase. An unprivileged attacker can open enough idle keep-alive connections to exhaust the process's file descriptors, causing the OS `accept()` syscall to fail and preventing any new connection — including legitimate `/construction/submit` requests that gossip transactions to the Hedera network.

### Finding Description

**Exact code path:**

`rosetta/app/config/types.go` lines 64–69 defines `Http.IdleTimeout` as a plain `time.Duration` with no minimum or maximum enforcement:
```go
type Http struct {
    IdleTimeout       time.Duration `yaml:"idleTimeout"`
    ...
}
```
Default value is `10000000000` ns (10 s) per `docs/configuration.md` line 662.

`rosetta/main.go` lines 220–227 constructs the `http.Server` using only timeout fields — no `ConnState` hook, no wrapped listener:
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
`httpServer.ListenAndServe()` (line 231) calls the standard library's `net.Listen` + `Accept` loop with no connection count cap.

**Root cause:** Go's `net/http.Server` has no built-in `MaxConns` field. The only stdlib-supported mechanisms to cap incoming connections are `golang.org/x/net/netutil.LimitListener` or a `ConnState` callback. A grep across all `rosetta/**/*.go` for `LimitListener`, `MaxConns`, `ConnState`, `netutil`, `semaphore`, and `connLimit` returns zero matches — none of these mitigations are present.

**Why the `IdleTimeout` does not prevent the attack:** `IdleTimeout` closes a connection that has been idle for 10 s. An attacker sends one valid HTTP request to open the connection (satisfying `ReadTimeout`/`WriteTimeout`), then goes silent. The server keeps the goroutine and file descriptor alive for 10 s. By opening new connections at a rate faster than 1 per 10 s per file-descriptor slot, the attacker maintains a saturated pool continuously.

**Traefik middleware is disabled by default:** `charts/hedera-mirror-rosetta/values.yaml` line 95 sets `global.middleware: false`. The middleware template (`charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3) gates on `{{ if and .Values.global.middleware .Values.middleware }}`, so the `inFlightReq: amount: 5` and `rateLimit: average: 10` rules (lines 152–160) are **never deployed** in a default installation. Even when enabled, `inFlightReq` limits active requests, not idle TCP connections.

### Impact Explanation

Each idle keep-alive connection consumes one OS file descriptor. Linux default `ulimit -n` for a process is 1024 (often raised to 65535 in containers, but still finite). Once all file descriptors are consumed, `accept()` returns `EMFILE`/`ENFILE`, and Go's HTTP server logs the error and stops accepting new connections. All subsequent `/construction/submit` POST requests are refused at the TCP layer — the signed transaction is never forwarded to a Hedera consensus node, blocking gossip of all pending transactions for the duration of the attack. The attack is a complete availability denial for the construction/submit workflow with no authentication required.

### Likelihood Explanation

The attack requires only the ability to open TCP connections to port 5700 (the default Rosetta port). No credentials, no valid Hedera account, no signed transaction needed. A single attacker machine can open thousands of connections with `curl --keepalive-time 9 -s http://target:5700/network/list &` in a loop, or with any tool that supports persistent connections (wrk, ab, custom socket code). The attack is repeatable and cheap: each connection costs ~1 KB of attacker memory and one file descriptor. The 10-second `IdleTimeout` means the attacker needs to sustain only ~(fd_limit / 10) new connections per second to maintain saturation — well within reach of a single commodity machine.

### Recommendation

1. **Wrap the listener with a connection cap** before passing it to `Serve`:
   ```go
   import "golang.org/x/net/netutil"
   ln, _ := net.Listen("tcp", fmt.Sprintf(":%d", rosettaConfig.Port))
   ln = netutil.LimitListener(ln, rosettaConfig.Http.MaxConnections) // add MaxConnections to Http struct
   httpServer.Serve(ln)
   ```
2. **Add `MaxConnections` to `Http` config struct** (`rosetta/app/config/types.go`) with a safe default (e.g., 1000).
3. **Enable the Traefik middleware by default** (`global.middleware: true`) so the `inFlightReq` and `rateLimit` rules are active in all deployments.
4. **Reduce `IdleTimeout`** to 2–5 s to shrink the window each connection occupies.

### Proof of Concept

```bash
# Open 2000 idle keep-alive connections to the Rosetta server
# Each sends one request then stays idle for up to IdleTimeout (10s)
for i in $(seq 1 2000); do
  curl -s --keepalive-time 9 --no-buffer \
    -H "Content-Type: application/json" \
    -d '{"metadata":{}}' \
    http://<ROSETTA_HOST>:5700/network/list \
    -o /dev/null &
done

# Now attempt a legitimate /construction/submit — connection will be refused
curl -v -X POST http://<ROSETTA_HOST>:5700/construction/submit \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{...},"signed_transaction":"0x..."}'
# Expected: connection refused or timeout — transaction never gossiped
```