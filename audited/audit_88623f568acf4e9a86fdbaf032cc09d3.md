### Title
Unauthenticated Plain-HTTP Mirror Node Bootstrap Allows Network Map Injection via ARP Spoofing

### Summary
When `cfg.network == "other"`, `newClient()` calls `buildNetworkFromMirrorNodes()`, which issues a plain HTTP GET (no TLS, no response-integrity check) to the mirror REST endpoint. An attacker on the same L2 segment who ARP-spoofs the mirror REST host can return a forged `nodesEnvelope`, causing `hiero.ClientForNetwork(netmap)` to build a Hiero SDK client whose entire node map points to attacker-controlled gRPC addresses. Every subsequent signed transaction is then delivered to the attacker.

### Finding Description

**Code path:**

`pinger/config.go` line 37 — the `mirrorRest` URL is configured with a plain `http://` example and no enforcement of HTTPS: [1](#0-0) 

`pinger/mirror_node_client.go` line 46 — the HTTP client has only a timeout; no TLS config, no certificate pinning, no transport-level security: [2](#0-1) 

`pinger/mirror_node_client.go` lines 79–98 — the GET is issued over plain HTTP and the response body is decoded directly into `nodesEnvelope` with no signature or integrity verification: [3](#0-2) 

`pinger/mirror_node_client.go` lines 100–124 — every `ServiceEndpoint` from the (potentially forged) payload is inserted verbatim into the `network` map: [4](#0-3) 

`pinger/sdk_client.go` lines 18–22 — the poisoned map is passed directly to `hiero.ClientForNetwork(netmap)`, replacing the entire node routing table: [5](#0-4) 

**Root cause:** The bootstrap HTTP call is unauthenticated and unencrypted. The only checks performed are an HTTP 2xx status code and a non-empty result set — both trivially satisfied by an attacker-controlled server. [6](#0-5) [7](#0-6) 

### Impact Explanation
The attacker receives every signed `CryptoTransfer` (and any other transaction) that the pinger submits. Because the Hiero SDK signs transactions client-side before sending them over gRPC, the attacker obtains fully-signed, replay-capable transaction bytes. The attacker can:
- Replay transactions on the real network to drain the operator account.
- Observe all transaction metadata (operator account ID, destination, amount).
- Silently drop transactions, causing liveness failures that are hard to distinguish from network issues.

Severity: **High** — direct financial loss and full transaction interception.

### Likelihood Explanation
The precondition (L2 adjacency for ARP spoofing) is realistic in:
- Kubernetes clusters where the pinger pod and the mirror-rest service share a node or a flat pod network.
- Any shared-cloud or co-hosted environment.
- CI/CD pipelines or staging environments with weaker network isolation.

The default example URL is `http://mirror-rest:5551` (plain HTTP), making this the expected deployment pattern, not an edge case. [1](#0-0) 

No special OS privileges are required to ARP-spoof in many container runtimes (e.g., pods without `NET_ADMIN` restrictions in permissive CNI configurations). The attack is repeatable on every pinger restart.

### Recommendation
1. **Enforce HTTPS** for `mirrorRest`: validate at startup that the URL scheme is `https://` and reject `http://`.
2. **TLS with certificate verification**: configure the `http.Client` with a `tls.Config` that pins the expected CA or server certificate for the mirror REST endpoint.
3. **Response integrity**: if the mirror node API supports signed responses or a known-good node list (e.g., embedded in the binary for well-known networks), verify the response against it before use.
4. **Restrict to known networks**: for the `"other"` case, consider requiring an operator-supplied, statically-configured node list rather than bootstrapping from a remote HTTP endpoint.

### Proof of Concept

**Preconditions:**
- Attacker is L2-adjacent to the pinger (same Kubernetes node, same VLAN, or same container network).
- `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.

**Steps:**

1. Attacker runs a rogue HTTP server on their machine that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{
      "domain_name": "attacker.example.com",
      "ip_address_v4": "",
      "port": 50211
    }]
  }],
  "links": {"next": null}
}
```
2. Attacker ARP-spoofs the pinger's ARP cache so that the IP of `mirror-rest` resolves to the attacker's MAC address.
3. Pinger starts, calls `buildNetworkFromMirrorNodes()` → `fetchMirrorNodeNetwork()` → HTTP GET is intercepted and the rogue server returns the forged payload.
4. `hiero.ClientForNetwork({"attacker.example.com:50211": AccountID{0,0,3}})` is called.
5. All subsequent `CryptoTransfer` gRPC calls are sent to `attacker.example.com:50211`.
6. Attacker's gRPC server logs the fully-signed transaction bytes and replays them against the real Hiero network.

### Citations

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L79-98)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}

	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```

**File:** pinger/mirror_node_client.go (L100-124)
```go
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
```

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```
