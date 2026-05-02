### Title
Unauthenticated Mirror Node Network Bootstrap Allows MITM Injection of Attacker-Controlled Consensus Node Addresses

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches the Hedera network topology over a plain, unauthenticated HTTP connection with no response integrity verification. An attacker capable of intercepting the HTTP request (via DNS spoofing, BGP hijacking, or ARP poisoning on the same network segment) can return a crafted `nodesEnvelope` JSON payload, causing `buildNetworkFromMirrorNodes()` to populate the SDK client's network map entirely with attacker-controlled gRPC endpoints. All subsequent `cryptoTransfer.Execute(client)` calls then submit signed transactions to the attacker's fake nodes rather than real consensus nodes, silently breaking the pinger's monitoring function.

### Finding Description

**Code path:**

`pinger/config.go` lines 37–38: `cfg.mirrorRest` is read from the `HIERO_MIRROR_PINGER_REST` environment variable with no scheme enforcement — the documented example is `http://mirror-rest:5551` (plain HTTP). [1](#0-0) 

`pinger/mirror_node_client.go` lines 36–44: `buildNetworkFromMirrorNodes()` constructs the URL directly from `cfg.mirrorRest` and passes it to `fetchMirrorNodeNetwork()` with a vanilla `http.Client` — no TLS configuration, no certificate pinning. [2](#0-1) 

`pinger/mirror_node_client.go` lines 74–131: `fetchMirrorNodeNetwork()` performs a plain `http.Get`, checks only the HTTP status code (lines 90–93), then blindly decodes the JSON body into `nodesEnvelope` and builds the network map from whatever `DomainName`/`IPAddressV4`/`Port` values the server returns. There is no allowlist of valid node addresses, no HMAC/signature check, and no TLS certificate validation. [3](#0-2) 

`pinger/sdk_client.go` lines 17–23: The returned map is passed directly to `hiero.ClientForNetwork(netmap)`, replacing the entire consensus node set with attacker-supplied addresses. [4](#0-3) 

`pinger/transfer.go` line 33: `cryptoTransfer.Execute(client)` then dials those attacker-controlled gRPC endpoints for every tick. [5](#0-4) 

**Root cause:** The code assumes the HTTP endpoint at `cfg.mirrorRest` is trustworthy and that the network path to it is secure. Neither assumption is enforced in code.

**Why existing checks are insufficient:** The only guard is an HTTP status-code range check (`200–299`). An attacker-controlled server trivially returns `200 OK` with a crafted body. There is no TLS, no certificate pinning, no response signature, and no allowlist of permitted node IPs or account IDs.

### Impact Explanation

When the attacker's fake gRPC endpoints receive the signed `CryptoTransfer` transactions:
- The real Hedera network never sees the transactions — real transfers do not occur.
- The pinger may receive a crafted gRPC success response and log false success metrics (`transfer success: status=SUCCESS`), masking genuine network outages.
- The monitoring signal the pinger is designed to produce becomes entirely unreliable.

**Correction on the question's on-chain claim:** The attacker's fake nodes cannot write falsified history to the real Hedera ledger — they have no consensus participation. The actual impact is **monitoring deception and silent DoS of the pinger**, not on-chain history falsification. This lowers severity from critical to high.

### Likelihood Explanation

- **Plain HTTP deployment** (the documented default `http://mirror-rest:5551`): any attacker on the same network segment (e.g., another pod in the same Kubernetes namespace, a compromised sidecar, or a cloud-internal MITM) can intercept with zero application-level privileges.
- **DNS spoofing**: if the mirror-rest hostname resolves via a cluster DNS server that can be poisoned or if the service is external, a DNS-level attacker redirects the connection.
- **BGP hijacking**: for externally reachable mirror node URLs, a BGP-capable adversary (ISP, nation-state) can reroute the prefix.
- The attack is repeatable: `buildNetworkFromMirrorNodes()` is called once at startup, so a single successful interception persists for the entire lifetime of the pinger process.

### Recommendation

1. **Enforce HTTPS** for `cfg.mirrorRest` and reject `http://` URLs at config validation time.
2. **Pin the TLS certificate or CA** for the mirror node REST endpoint using a custom `tls.Config` on the `http.Client`.
3. **Validate returned node addresses** against a static allowlist of known Hedera consensus node account IDs (e.g., `0.0.3`–`0.0.28` for mainnet) before accepting them into the network map.
4. **Re-fetch and reconcile** the network map periodically rather than trusting a single bootstrap response for the entire process lifetime.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (plain HTTP).
- Attacker controls DNS resolution for `mirror-rest` or is on-path (e.g., same Kubernetes namespace).

**Steps:**

1. Stand up a malicious HTTP server that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "ip_address_v4": "attacker.example.com", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
```
2. Redirect DNS for `mirror-rest` to the attacker's server (or ARP-spoof the path).
3. Start the pinger. `buildNetworkFromMirrorNodes()` fetches the crafted response and returns `{"attacker.example.com:50211": AccountID{0,0,3}}`.
4. `hiero.ClientForNetwork(netmap)` creates a client pointing solely at `attacker.example.com:50211`.
5. Every tick, `cryptoTransfer.Execute(client)` dials the attacker's gRPC server. The attacker returns a fake `SUCCESS` receipt.
6. The pinger logs `transfer success` indefinitely while no real transfers occur on the Hedera network.

### Citations

**File:** pinger/config.go (L37-38)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")

```

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

**File:** pinger/mirror_node_client.go (L74-131)
```go
func fetchMirrorNodeNetwork(
	ctx context.Context,
	httpClient *http.Client,
	url string,
) (map[string]hiero.AccountID, bool, error) {
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

	return network, false, nil
```

**File:** pinger/sdk_client.go (L17-23)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)

```

**File:** pinger/transfer.go (L33-33)
```go
		resp, err := cryptoTransfer.Execute(client)
```
