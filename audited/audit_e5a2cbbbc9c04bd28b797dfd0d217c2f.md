### Title
Unauthenticated HTTP Endpoint for Mirror Node Discovery Enables MITM Network Poisoning

### Summary
`buildNetworkFromMirrorNodes` in `pinger/mirror_node_client.go` constructs a plain `http.Client` with no TLS enforcement and fetches node topology from `cfg.mirrorRest` over an unencrypted channel. An attacker with network-path access between the pinger and the mirror REST endpoint can intercept the HTTP response and inject a crafted `nodesEnvelope` containing attacker-controlled `service_endpoints`, causing `hiero.ClientForNetwork(netmap)` to route all subsequent `TransferTransaction` executions to a black-hole address. Because the pinger never re-fetches the node list after startup, the poisoned network map persists for the entire process lifetime.

### Finding Description

**Code path:**

- `pinger/config.go` line 37: `mirrorRest` accepts any URL string; the documented default is `http://mirror-rest:5551`. No validation enforces `https://`.
- `pinger/mirror_node_client.go` line 46: `httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}` — a bare `http.Client` with no custom `Transport`, no TLS config, no certificate pinning.
- Lines 79–84: `http.NewRequestWithContext` + `httpClient.Do(req)` issues a plaintext GET to the constructed URL.
- Lines 95–98: The response body is decoded directly into `nodesEnvelope` with no integrity check, no signature verification, and no allowlist of legitimate node addresses.
- Lines 102–124: Every `serviceEndpoint` with a non-empty host and non-zero port is unconditionally inserted into the `network` map.
- `pinger/sdk_client.go` lines 18–22: `hiero.ClientForNetwork(netmap)` is called once at startup with this map; the client is never refreshed.
- `pinger/transfer.go` lines 29–33: Every tick calls `cryptoTransfer.Execute(client)` using the poisoned client.

**Root cause:** The code assumes the mirror REST endpoint is trusted and reachable only over a secure channel. Neither assumption is enforced in code. The `http.Client` will silently follow any HTTP URL, and the parsed JSON is used verbatim to build the consensus-node routing table.

**Why existing checks fail:**
- Line 103 (`NodeAccountID == ""`) only skips structurally empty entries; an attacker supplies a syntactically valid account ID string.
- Line 107 (`AccountIDFromString`) validates format only, not legitimacy.
- Line 118 (`host == "" || ep.Port == 0`) only skips degenerate entries; attacker supplies a real-looking host:port.
- Line 127 (`len(network) == 0`) only rejects a completely empty result; attacker returns exactly one valid-looking entry.

### Impact Explanation
All `AddHbarTransfer` transactions are signed with the operator's real private key and dispatched to the attacker's endpoint. The transactions never reach the Hedera consensus network, so no on-chain error is produced and no receipt is returned. The pinger logs retry failures but continues sending to the same poisoned map indefinitely. Intended HBAR transfers never settle; from the recipient's perspective funds are permanently withheld for the process lifetime. Because the client is built once at startup (`main.go` line 41–44), recovery requires a process restart with a clean network path.

### Likelihood Explanation
The attack requires the adversary to sit on the network path between the pinger pod and the mirror REST service. In typical Kubernetes deployments without strict `NetworkPolicy` enforcement, any pod in the cluster can perform ARP spoofing or DNS poisoning against the `mirror-rest` service name. The documented default URL (`http://mirror-rest:5551`) is an in-cluster plain-HTTP address, making this the expected deployment topology. No credentials, no special OS privileges, and no Hedera account are required — only L2/L3 network adjacency or DNS control within the cluster.

### Recommendation
1. **Enforce HTTPS:** Validate at config load time that `cfg.mirrorRest` has an `https` scheme; reject `http` URLs. In `config.go`, after line 133, add a scheme check.
2. **Pin the CA / use mTLS:** Supply a custom `http.Transport` with a restricted `TLSClientConfig` that pins the mirror node's CA certificate.
3. **Validate returned node addresses:** Maintain an operator-supplied allowlist of legitimate consensus-node account IDs and reject any `NodeAccountID` not on the list.
4. **Periodic refresh with change detection:** Re-fetch the node list periodically and alert/abort on unexpected topology changes rather than trusting a single startup fetch.

### Proof of Concept
1. Deploy the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
2. From any pod in the same Kubernetes namespace, poison DNS so `mirror-rest` resolves to an attacker-controlled IP, or use ARP spoofing to intercept traffic to the real mirror-rest pod.
3. Serve the following JSON on `GET /api/v1/network/nodes`:
   ```json
   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"203.0.113.1","port":50211}]}],"links":{"next":null}}
   ```
   where `203.0.113.1` is a black-hole address.
4. Start (or restart) the pinger. `buildNetworkFromMirrorNodes` fetches the poisoned response; `hiero.ClientForNetwork` builds a map pointing solely to `203.0.113.1:50211`.
5. Observe that every subsequent `cryptoTransfer.Execute(client)` times out or returns a connection error; no transaction is submitted to the real Hedera network; the intended recipient never receives HBAR; the pinger runs indefinitely in this broken state with no on-chain evidence of the attack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** pinger/mirror_node_client.go (L100-129)
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
	}

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```
