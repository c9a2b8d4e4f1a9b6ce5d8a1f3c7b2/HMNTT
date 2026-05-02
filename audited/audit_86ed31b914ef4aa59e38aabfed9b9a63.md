### Title
Rogue Mirror REST Server Can Crash-Loop the Pinger via All-Zero-Port `nodesEnvelope` Response

### Summary
When `network=other`, the pinger fetches its consensus-node map from a mirror REST URL. If every `serviceEndpoint` in the response carries `port=0`, all entries are silently skipped, the resulting network map is empty, and `fetchMirrorNodeNetwork` returns `retry=false`. This bypasses every configured retry, causes `newClient()` to return an error, and `main()` calls `log.Fatalf()`, terminating the process. An attacker who can serve or intercept that HTTP response can keep the pinger in a permanent crash-loop.

### Finding Description

**Code path:**

1. `main.go:41-43` — `newClient()` failure is fatal: [1](#0-0) 

2. `sdk_client.go:18-21` — for `network=other`, `buildNetworkFromMirrorNodes` error propagates directly: [2](#0-1) 

3. `mirror_node_client.go:113-124` — `port=0` silently skips every endpoint: [3](#0-2) 

4. `mirror_node_client.go:127-129` — empty map returns `retry=false`: [4](#0-3) 

5. `mirror_node_client.go:59` — `retry=false` breaks the retry loop on the very first attempt, regardless of `mirrorNodeClientMaxRetries`: [5](#0-4) 

**Root cause:** The code treats "no usable endpoints" as a non-retryable, permanent error (`retry=false`). Combined with `log.Fatalf` in `main`, a single poisoned HTTP response terminates the process. There is no minimum-endpoint validation, no TLS enforcement on the mirror REST URL, and no fallback.

### Impact Explanation
The pinger process exits via `log.Fatalf`. If managed by a container orchestrator (Kubernetes), it enters a crash-loop as long as the attacker continues serving the malicious payload. The `/tmp/ready` readiness file is never written, so liveness/readiness probes fail, and the pod is never marked healthy. No transfers are submitted, which is the sole purpose of the pinger. Severity is Medium/DoS with no direct economic loss.

### Likelihood Explanation
Preconditions: `network=other` must be configured (required for private/custom networks), and the attacker must be able to serve or intercept the HTTP response from `mirrorRest`. The example config uses plain `http://` (no TLS), making DNS poisoning, ARP spoofing, or a compromised internal mirror node sufficient. No credentials or privileged access to the pinger host are needed. The attack is repeatable: every container restart re-fetches the node list, so the crash-loop persists indefinitely.

### Recommendation
1. Change the empty-network case to return `retry=true` so all configured retries are exhausted before failing.
2. In `main`, treat `newClient` failure as a retryable startup error (loop with backoff) rather than calling `log.Fatalf`.
3. Enforce a minimum valid-endpoint count (e.g., ≥1 endpoint with port in 1–65535).
4. Require or strongly recommend HTTPS for `mirrorRest` URLs; log a warning when plain HTTP is detected.

### Proof of Concept
1. Stand up an HTTP server that always returns:
   ```json
   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"domain_name":"node.example.com","port":0}]}],"links":{}}
   ```
2. Configure the pinger: `HIERO_MIRROR_PINGER_NETWORK=other`, `HIERO_MIRROR_PINGER_REST=http://<attacker-server>/api/v1`.
3. Start the pinger. Observe `log.Fatalf("client error: no usable service_endpoints found …")` and immediate process exit.
4. Restart the pinger (simulating orchestrator restart); it exits again immediately, demonstrating the crash-loop.

### Citations

**File:** pinger/main.go (L41-43)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
```

**File:** pinger/sdk_client.go (L17-21)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/mirror_node_client.go (L59-61)
```go
		if !retry || attempt == attempts {
			break
		}
```

**File:** pinger/mirror_node_client.go (L113-124)
```go
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
```

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```
