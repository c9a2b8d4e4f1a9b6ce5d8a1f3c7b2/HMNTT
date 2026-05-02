All code references verified against the actual source. Here is the assessment:

---

Audit Report

## Title
Unauthenticated Mirror REST Response with Empty `nodes` Array Causes Non-Retryable Pinger Shutdown

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` returns a non-retryable error when the mirror REST endpoint responds with HTTP 200 and an empty `nodes` array. Because `buildNetworkFromMirrorNodes()` immediately breaks on a non-retryable error, all configured retries are bypassed. `newClient()` propagates this error to `main()`, which calls `log.Fatalf`, terminating the pinger process entirely with no recovery path.

## Finding Description
**Verified code path:**

`fetchMirrorNodeNetwork()` (lines 74–131) iterates over `payload.Nodes` at lines 102–125 to build the `network` map. If the response body is `{"nodes":[],"links":{"next":null}}` with HTTP 200, the loop never executes and `network` remains empty. The guard at lines 127–129 then fires:

```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
``` [1](#0-0) 

The second return value `false` signals "do not retry." Back in `buildNetworkFromMirrorNodes()` at lines 58–61:

```go
lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
if !retry || attempt == attempts {
    break
}
``` [2](#0-1) 

`retry=false` causes an immediate `break` on the very first attempt, bypassing all retries configured via `mirrorNodeClientMaxRetries` (default 10). [3](#0-2) 

`newClient()` in `sdk_client.go` propagates this error at lines 19–21: [4](#0-3) 

`main()` calls `log.Fatalf` on this error at lines 42–44, terminating the process: [5](#0-4) 

There is no periodic re-initialization after startup failure; `newClient()` is called exactly once.

**Failed assumption:** The code treats an empty-nodes 200 response as a definitive, permanent condition (non-retryable), rather than a potentially transient or adversarial one.

## Impact Explanation
The pinger process exits via `log.Fatalf` and cannot recover without a manual restart. No SDK client is created, no transactions are submitted, and the `/tmp/ready` readiness file is never written. [6](#0-5)  In deployments where the pinger's transaction success rate gates alerts or automated responses, this constitutes a complete denial-of-service against network observability. Severity: **Medium** — DoS on the pinger monitoring layer; consensus nodes are unaffected.

## Likelihood Explanation
**Preconditions:**
- `network=other` must be configured (the only code path that calls `buildNetworkFromMirrorNodes`). [7](#0-6) 
- The attacker must either (a) control the configured mirror REST endpoint (malicious or compromised mirror node operator), or (b) perform a MITM attack on a plaintext `http://` connection. The default example URL in config is `http://mirror-rest:5551`. [8](#0-7) 

The attack is trivially repeatable: serve `{"nodes":[]}` on every request and the pinger never recovers, because the retry loop is bypassed unconditionally on the first attempt.

## Recommendation
1. **Treat empty-nodes as retryable:** Change the return at line 128 to `return nil, true, fmt.Errorf(...)` so that a 200-with-empty-nodes response is retried like a transient failure, consistent with how network errors are handled at line 86. [9](#0-8) 
2. **Enforce TLS:** Validate that `cfg.mirrorRest` uses `https://` when `network=other`, or document that plaintext HTTP is only acceptable on a trusted private network.
3. **Periodic re-initialization:** Consider re-running `buildNetworkFromMirrorNodes` on a background ticker rather than only at startup, so a transient bad response does not permanently halt the pinger.

## Proof of Concept
Stand up an HTTP server that always responds:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"nodes":[],"links":{"next":null}}
```
Configure the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-server>`. On startup, `fetchMirrorNodeNetwork` returns `(nil, false, error)` on the first attempt; `buildNetworkFromMirrorNodes` breaks immediately despite `mirrorNodeClientMaxRetries=10`; `newClient` returns the error; `main` calls `log.Fatalf` and the process exits. No transactions are ever submitted regardless of how many times the container is restarted (the same response is served each time).

### Citations

**File:** pinger/mirror_node_client.go (L58-61)
```go
		lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		if !retry || attempt == attempts {
			break
		}
```

**File:** pinger/mirror_node_client.go (L84-87)
```go
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
	}
```

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/config.go (L72-81)
```go
	mirrorNodeClientMaxRetriesStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_MAX_RETRIES", "10")
	flag.Func("mirror-node-client-max-retries", "max retries for mirror node client requests", func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		cfg.mirrorNodeClientMaxRetries = v
		return nil
	})
	_ = flag.CommandLine.Set("mirror-node-client-max-retries", mirrorNodeClientMaxRetriesStr)
```

**File:** pinger/sdk_client.go (L16-22)
```go
	switch cfg.network {
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/main.go (L46-49)
```go
	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```
