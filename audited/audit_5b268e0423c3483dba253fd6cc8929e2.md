### Title
Unauthenticated HTTP Fetch of Node Topology Enables MITM Node-Substitution in `buildNetworkFromMirrorNodes()`

### Summary
`buildNetworkFromMirrorNodes()` in `pinger/mirror_node_client.go` issues a plain HTTP GET to `cfg.mirrorRest` with no TLS enforcement, no scheme validation, and no integrity check on the returned `nodesEnvelope`. A network-adjacent attacker who can intercept or spoof that HTTP response can inject arbitrary gRPC endpoints, causing the Hiero SDK client to route all subsequent fee-bearing `CryptoTransfer` transactions exclusively to attacker-controlled nodes. This requires no credentials and no access to the pinger process itself.

### Finding Description
**Code path:**

- `pinger/config.go` line 37: `mirrorRest` is accepted from the env var `HIERO_MIRROR_PINGER_REST`; the help text explicitly shows `http://mirror-rest:5551` as the expected value. No scheme validation is performed anywhere.
- `pinger/mirror_node_client.go` lines 46–53: A bare `&http.Client{Timeout: cfg.mirrorNodeClientTimeout}` is constructed — no custom `Transport`, no TLS config, no certificate pinning.
- `pinger/mirror_node_client.go` lines 79–98: `http.NewRequestWithContext` issues a GET to the constructed URL; the response body is decoded directly into `nodesEnvelope` with `json.NewDecoder(resp.Body).Decode(&payload)`.
- `pinger/mirror_node_client.go` lines 100–124: Every `host:port` pair from the attacker-controlled JSON is inserted verbatim into the `network` map with no allowlist, no IP validation, and no domain check.
- `pinger/sdk_client.go` lines 18–22: The poisoned `network` map is passed directly to `hiero.ClientForNetwork(netmap)`, replacing the entire node topology for the SDK client.
- `pinger/transfer.go` lines 29–33: All `CryptoTransfer` executions use this client, so every transaction is dispatched to the attacker-supplied endpoints.

**Root cause:** The code assumes the HTTP channel to the mirror REST API is trustworthy. There is no enforcement that `cfg.mirrorRest` uses `https://`, no TLS verification, and no cryptographic integrity check on the returned node list.

**Why existing checks fail:** The only validation on the response is a non-2xx status check (line 90–93) and a non-empty `node_account_id` check (line 103). Neither prevents an attacker from returning a well-formed 200 OK with rogue endpoints.

### Impact Explanation
Once the SDK client is initialized with attacker-controlled node endpoints:
1. **Node fee extraction**: Hedera's fee model splits fees between network, service, and node. The node portion accrues to whichever node receives the transaction. An attacker-controlled node collects node fees on every `CryptoTransfer` tick (default: every 1 second, `cfg.interval`).
2. **Transaction DoS**: The rogue node can silently drop all submitted transactions, causing the pinger to report continuous failures while the operator's account is debited retry fees.
3. **Traffic observation**: All signed transaction bytes, operator account IDs, and destination account IDs are exposed to the attacker's gRPC endpoint.

The transaction amounts and destinations are protected by the operator's private key signature, so funds cannot be redirected beyond what the signed transaction specifies. However, fee extraction and DoS are fully achievable.

### Likelihood Explanation
The preconditions are realistic in typical deployment environments:
- `network=other` is the only supported mode for private/custom networks, which is the primary use case for self-hosted mirror node deployments.
- The documented example URL (`http://mirror-rest:5551`) is plaintext HTTP, making this the expected configuration.
- In Kubernetes, a compromised pod in the same namespace can perform ARP spoofing or DNS hijacking against cluster-internal service names. An attacker with any foothold in the cluster (e.g., via a compromised sidecar or shared node) can intercept unencrypted intra-cluster HTTP traffic.
- The attack is repeatable: the node map is fetched once at startup, so a single successful MITM poisons the client for its entire lifetime.

No privileged access to the pinger process, its configuration, or the mirror node is required.

### Recommendation
1. **Enforce HTTPS**: Validate that `cfg.mirrorRest` starts with `https://` and reject `http://` at config load time in `loadConfig()` (or at minimum emit a fatal warning).
2. **Pin or verify TLS**: Configure the `http.Client` transport with a specific CA bundle or certificate fingerprint for the mirror REST endpoint.
3. **Validate returned endpoints**: After fetching the node list, cross-check returned IP addresses and account IDs against a locally configured allowlist or a separately obtained, integrity-protected source.
4. **Re-fetch periodically with integrity checks**: If the node list must be refreshed at runtime, apply the same TLS and validation requirements to each refresh.

### Proof of Concept
**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
- Attacker has network-adjacent position (e.g., compromised pod in the same Kubernetes namespace).

**Steps:**
1. Attacker intercepts DNS or ARP for `mirror-rest` and stands up a rogue HTTP server on port 5551.
2. Rogue server responds to `GET /api/v1/network/nodes` with:
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
3. Pinger starts, calls `buildNetworkFromMirrorNodes()`, receives the crafted response, and builds `network = {"attacker.example.com:50211": AccountID{0,0,3}}`.
4. `hiero.ClientForNetwork(network)` initializes the SDK client pointing solely at `attacker.example.com:50211`.
5. Every subsequent `CryptoTransfer.Execute(client)` in `submitWithRetry()` sends the signed transaction to the attacker's gRPC endpoint.
6. Attacker's node collects node fees on each transaction and/or drops transactions to cause continuous DoS. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** pinger/mirror_node_client.go (L36-46)
```go
func buildNetworkFromMirrorNodes(ctx context.Context, cfg config) (map[string]hiero.AccountID, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.mirrorRest), "/")

	var url string
	if strings.HasSuffix(base, "/api/v1") {
		url = base + "/network/nodes"
	} else {
		url = base + "/api/v1/network/nodes"
	}

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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
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
