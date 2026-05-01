### Title
Null `nodes` Field in Mirror REST Response Causes Pinger to Terminate with No Retry, Masking Node Shutdowns

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the mirror REST response into a `nodesEnvelope` struct without validating that `payload.Nodes` is non-nil. When an attacker-controlled or compromised mirror REST endpoint returns `{"nodes": null, ...}`, the range loop produces zero iterations, `len(network) == 0` triggers an error returned with `retry=false`, and `buildNetworkFromMirrorNodes()` immediately propagates the failure without retrying. This causes `newClient()` to fail and `main()` to call `log.Fatalf`, terminating the pinger entirely and masking any ongoing node shutdowns.

### Finding Description

**Code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 95–129:

```go
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {   // line 96
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}

network := make(map[string]hiero.AccountID)

for _, n := range payload.Nodes {   // line 102 — nil slice: zero iterations, no panic
    ...
}

if len(network) == 0 {              // line 127
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
    //              ^^^^^ retry=false: caller will NOT retry
}
```

**Root cause:** Go's `encoding/json` sets a slice field to `nil` when the JSON value is `null`. Ranging over a nil slice is valid Go and simply produces zero iterations. There is no guard checking `payload.Nodes != nil` before the loop. The `len(network) == 0` guard at line 127 correctly detects the empty result but returns `retry=false`, which is the critical flaw.

**Retry bypass:** In `buildNetworkFromMirrorNodes()` (lines 59–61):
```go
if !retry || attempt == attempts {
    break
}
```
Because `retry=false` is returned, the loop breaks after the very first attempt regardless of `cfg.mirrorNodeClientMaxRetries`. All configured retries are skipped.

**Pinger termination:** `newClient()` in `sdk_client.go` (lines 18–21) propagates the error directly:
```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
if err != nil {
    return nil, err
}
```
`main.go` line 43 then calls `log.Fatalf("client error: %v", err)`, which terminates the process.

### Impact Explanation
The pinger's sole purpose is to detect network node shutdowns by continuously submitting transfers. If the pinger process is killed at startup (or on any restart), it stops emitting transfer metrics entirely. An operator monitoring for failed transfers would see silence rather than failures — indistinguishable from a healthy network — masking a shutdown of ≥30% of processing nodes. The impact is a complete blind spot in the monitoring system for the duration the pinger remains down.

### Likelihood Explanation
The default example URL in `config.go` is `http://mirror-rest:5551` (plaintext HTTP). On any deployment using HTTP:
- A network-adjacent attacker (same Kubernetes namespace, compromised sidecar, ARP spoofing on a flat network) can intercept the single HTTP GET to `/api/v1/network/nodes` and return `{"nodes":null,"links":{}}`.
- DNS poisoning of the mirror REST hostname achieves the same result from a more external position.
- The attack is a single HTTP response injection — no credentials, no brute force, no sustained access required.
- Because `retry=false` is returned, even one poisoned response is sufficient to terminate the pinger.
- The attack is repeatable on every pinger restart (e.g., after a Kubernetes pod restart).

### Recommendation
1. **Validate non-null, non-empty nodes before accepting the response:**
   ```go
   if payload.Nodes == nil {
       return nil, false, fmt.Errorf("mirror node response contained null nodes field from %s", url)
   }
   ```
2. **Return `retry=true` for an empty/null nodes result** so that transient poisoning or a temporarily degraded mirror does not permanently kill the pinger:
   ```go
   if len(network) == 0 {
       return nil, true, fmt.Errorf("no usable service_endpoints found from %s", url)
   }
   ```
3. **Enforce HTTPS** for the mirror REST endpoint and validate the server certificate, removing the MITM attack surface entirely.
4. **Cross-validate** the node list against a secondary mirror or a locally pinned minimum node count to detect implausible responses (e.g., zero nodes when the network is known to have many).

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (HTTP, not HTTPS).
- Attacker has network-adjacent access (same pod network, ARP spoof, or DNS control).

**Steps:**
1. Stand up a mock HTTP server that responds to any GET with:
   ```json
   {"nodes": null, "links": {"next": null}}
   ```
2. Redirect DNS or ARP-spoof `mirror-rest` to point to the mock server.
3. Start (or restart) the pinger.
4. The pinger calls `buildNetworkFromMirrorNodes()` → `fetchMirrorNodeNetwork()`.
5. JSON decodes successfully; `payload.Nodes` is `nil`.
6. Range loop executes zero iterations; `network` remains empty.
7. `len(network) == 0` → returns `nil, false, error`.
8. `buildNetworkFromMirrorNodes()` breaks immediately (retry=false), returns the error.
9. `newClient()` returns the error.
10. `main()` calls `log.Fatalf` → pinger process exits.
11. No transfer metrics are emitted; node shutdowns go undetected. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L52-61)
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
```

**File:** pinger/mirror_node_client.go (L95-129)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}

	network := make(map[string]hiero.AccountID)

	for _, n := range payload.Nodes {
		if n.NodeAccountID == "" {
			continue
		}

		nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
		if err != nil {
			continue
		}

		// Use service_endpoints for node gRPC (what the SDK wants)
		for _, ep := range n.ServiceEndpoints {
			host := strings.TrimSpace(ep.DomainName)
			if host == "" {
				host = strings.TrimSpace(ep.IPAddressV4)
			}
			if host == "" || ep.Port == 0 {
				continue
			}

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
			network[addr] = nodeAccountId
		}
	}

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/sdk_client.go (L18-21)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```
