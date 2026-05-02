### Title
BGP Hijack via Plain-HTTP Mirror REST Endpoint Exhausts All Retries and Terminates the Pinger Process

### Summary
`buildNetworkFromMirrorNodes` constructs an `http.Client` with no TLS enforcement and no certificate pinning, and the documented example URL uses plain `http://`. An attacker who can BGP-hijack the mirror REST server's IP range can intercept every HTTP request and return HTTP 500, which the retry logic treats as a retryable error. After all retries are exhausted the function returns an error that propagates to `log.Fatalf`, terminating the pinger process entirely and permanently halting transaction confirmation until a manual restart.

### Finding Description

**Code path and root cause**

`pinger/sdk_client.go` line 18 calls `buildNetworkFromMirrorNodes` exactly once at startup, inside `newClient`:

```go
// sdk_client.go:18-21
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
if err != nil {
    return nil, err
}
```

`newClient`'s error is handled in `main.go` lines 42-44 with `log.Fatalf`, which calls `os.Exit(1)`:

```go
client, err := newClient(cfg)
if err != nil {
    log.Fatalf("client error: %v", err)
}
```

Inside `buildNetworkFromMirrorNodes` (`mirror_node_client.go` lines 46-71), the HTTP client is created with no custom transport, no TLS configuration, and no certificate pinning:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

The URL is taken verbatim from `cfg.mirrorRest`. The documented example in `config.go` line 37 is `http://mirror-rest:5551` — plain HTTP.

In `fetchMirrorNodeNetwork` lines 90-92, HTTP 500 sets `retry = true`:

```go
retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
```

The retry loop in `buildNetworkFromMirrorNodes` lines 52-71 will keep retrying (up to `mirrorNodeClientMaxRetries + 1` attempts, default 11) and then return `nil, lastErr`.

**Exploit flow**

1. Operator deploys pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<mirror-ip>:5551` (plain HTTP, as documented).
2. Attacker announces a more-specific BGP prefix covering `<mirror-ip>`, redirecting traffic to an attacker-controlled host.
3. Attacker's host accepts TCP connections on port 5551 and returns `HTTP/1.1 500 Internal Server Error` for every request.
4. Each call to `fetchMirrorNodeNetwork` returns `(nil, true, error)`.
5. The retry loop exhausts all 11 attempts (default), then `buildNetworkFromMirrorNodes` returns `(nil, lastErr)`.
6. `newClient` returns the error; `main.go` calls `log.Fatalf` → `os.Exit(1)`.
7. The pinger process terminates. No transactions are ever submitted or confirmed.

**Why existing checks are insufficient**

- The retry logic correctly marks HTTP 500 as retryable (for legitimate transient server errors), but this is exactly what the attacker exploits — every retry hits the attacker's server.
- There is no HTTPS enforcement, no certificate pinning, and no fallback to a secondary mirror endpoint.
- There is no re-initialization loop in `main.go`; a single failure at startup is fatal.

### Impact Explanation

For any deployment using `network=other` (private/custom networks), the pinger process exits immediately at startup and never recovers autonomously. No Hedera transactions are submitted, so the monitoring/liveness function of the pinger is completely disabled. This constitutes a total network-confirmation shutdown for the monitored environment for as long as the BGP hijack persists.

### Likelihood Explanation

BGP hijacking of a specific IP prefix is a documented, real-world attack class (e.g., 2018 Amazon Route 53 hijack, 2010 China Telecom incident). It requires control of or access to an upstream BGP router or AS — not a typical end-user capability, but well within reach of a nation-state actor, a compromised ISP, or an insider at a transit provider. The attack is repeatable: every time the pinger is restarted while the hijack is active, it will fail again at the same point. The use of plain HTTP (the documented default) removes the only natural mitigation (TLS certificate validation).

### Recommendation

1. **Enforce HTTPS** for `mirrorRest` URLs; reject `http://` schemes at config validation time in `loadConfig()`.
2. **Add certificate pinning or a custom `tls.Config`** with a known CA pool for the mirror REST endpoint.
3. **Do not use `log.Fatalf` for a recoverable startup condition**; instead, retry `buildNetworkFromMirrorNodes` in a loop with backoff inside `main`, so a transient (or attacker-induced) failure does not permanently kill the process.
4. **Support multiple mirror REST endpoints** so that if one is unreachable, another can be tried.

### Proof of Concept

```
# Preconditions:
# - Attacker controls a BGP router that can announce a more-specific prefix
#   for the IP of the mirror REST server.
# - Pinger is configured with HIERO_MIRROR_PINGER_NETWORK=other
#   and HIERO_MIRROR_PINGER_REST=http://<mirror-ip>:5551

# Step 1: Attacker announces BGP prefix, redirecting <mirror-ip> to attacker host.

# Step 2: On attacker host, run a minimal HTTP server returning 500:
python3 -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 5551)); s.listen(10)
while True:
    c, _ = s.accept()
    c.recv(4096)
    c.sendall(b'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n')
    c.close()
"

# Step 3: Start the pinger.
# Expected result: pinger logs 11 failed attempts then calls log.Fatalf and exits.
# Output observed:
#   attempt 1/11: GET http://<mirror-ip>:5551/api/v1/network/nodes returned 500 Internal Server Error
#   ...
#   attempt 11/11: ...
#   client error: attempt 11/11: GET http://<mirror-ip>:5551/api/v1/network/nodes returned 500 Internal Server Error
#   exit status 1
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L52-71)
```go
	for attempt := 1; attempt <= attempts; attempt++ {
		network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
		if err == nil {
			return network, nil
		}

		lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		if !retry || attempt == attempts {
			break
		}

		backoff := cfg.mirrorNodeClientBaseBackoff * time.Duration(1<<(attempt-1))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	return nil, lastErr
```

**File:** pinger/mirror_node_client.go (L90-92)
```go
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
```

**File:** pinger/sdk_client.go (L18-21)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/main.go (L42-44)
```go
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
