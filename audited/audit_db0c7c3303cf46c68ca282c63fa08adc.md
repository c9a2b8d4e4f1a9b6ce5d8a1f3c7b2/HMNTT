### Title
Unauthenticated HTTP Mirror Node Bootstrap Enables Network Map Poisoning via MitM

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches the Hiero node list over a plain HTTP connection with no scheme enforcement, no TLS, and no response integrity verification. An attacker positioned on the network path (ARP spoofing on the same L2 segment, DNS poisoning, or BGP hijacking for internet-facing deployments) can intercept the GET `/api/v1/network/nodes` response and inject attacker-controlled gRPC endpoints. The pinger then builds its entire `hiero.Client` network map from this poisoned data, directing all subsequent signed transactions — including those carrying the operator private key — to attacker-controlled nodes.

### Finding Description

**Exact code path:**

`pinger/config.go` line 37 — the `mirrorRest` field accepts any URL string with no scheme validation. The documented example is explicitly `http://mirror-rest:5551`: [1](#0-0) 

`pinger/mirror_node_client.go` lines 36–44 — `buildNetworkFromMirrorNodes()` takes `cfg.mirrorRest` verbatim and constructs the request URL with no HTTPS enforcement: [2](#0-1) 

`pinger/mirror_node_client.go` lines 46–46 — a plain `http.Client` is constructed with no TLS configuration, no certificate pinning, no custom transport: [3](#0-2) 

`pinger/mirror_node_client.go` lines 79–97 — `fetchMirrorNodeNetwork()` issues the GET request and decodes the response body with zero integrity verification: [4](#0-3) 

`pinger/mirror_node_client.go` lines 100–124 — the decoded `host:port` pairs from the JSON response are inserted directly into the `network` map that becomes the SDK's node list: [5](#0-4) 

`pinger/sdk_client.go` lines 18–22 — this poisoned map is passed directly to `hiero.ClientForNetwork()`: [6](#0-5) 

**Root cause:** No HTTPS scheme is enforced on `cfg.mirrorRest`. The `http.Client` has no TLS transport, no certificate pinning, and the JSON response carries no cryptographic signature. The code unconditionally trusts whatever JSON body is returned.

**Failed assumption:** The code assumes the HTTP response from the mirror node is authentic and unmodified. This assumption fails whenever the network path is not physically secured.

**Exploit flow:**
1. Attacker positions themselves on the network path between the pinger and the mirror REST endpoint (ARP spoofing on the same subnet, DNS cache poisoning if a hostname is used, or BGP hijacking for routed deployments).
2. Attacker intercepts the HTTP GET to `/api/v1/network/nodes`.
3. Attacker returns a crafted `nodesEnvelope` JSON with `service_endpoints` pointing to attacker-controlled gRPC servers.
4. `fetchMirrorNodeNetwork()` decodes this without any integrity check and returns the poisoned map.
5. `hiero.ClientForNetwork(netmap)` builds the SDK client targeting attacker nodes.
6. All subsequent `submitWithRetry()` calls send signed Hiero transactions to the attacker's gRPC servers.

**Existing checks reviewed and shown insufficient:**
- HTTP status code check (lines 90–93) — only validates the attacker's own spoofed response returns 2xx. [7](#0-6) 
- Non-empty network map check (lines 127–129) — only verifies the attacker supplied at least one endpoint. [8](#0-7) 
- Neither check provides any cryptographic or transport-layer authenticity guarantee.

### Impact Explanation
The pinger's operator private key signs every transfer transaction. Once the network map is poisoned, all signed transaction bytes are delivered to attacker-controlled gRPC servers. The attacker can: (a) observe and record all signed transactions including the operator account ID and key usage patterns; (b) selectively drop transactions causing a liveness failure; (c) replay captured signed transactions against the real network if they are not yet expired. The `operatorKey` default in config is a well-known test key, but in production deployments this is a funded account key. The `toAccountID` and `amountTinybar` are also attacker-visible. This is a bootstrap-time attack — a single successful interception poisons the entire lifetime of the pinger process.

### Likelihood Explanation
The vulnerability is only reachable when `network=other` is configured, but the documented example URL is `http://mirror-rest:5551` (plain HTTP), making HTTP the expected and common deployment pattern for this mode. In Kubernetes or Docker deployments (the target environment given the `Dockerfile` present), ARP spoofing between pods on the same node or VLAN is achievable by any compromised container in the cluster without elevated host privileges. DNS poisoning of an internal service name requires only control of the cluster DNS or a rogue pod. BGP hijacking applies to internet-facing mirror endpoints. The attack is repeatable on every pinger restart.

### Recommendation
1. **Enforce HTTPS at config load time:** In `loadConfig()`, after parsing `cfg.mirrorRest`, reject any URL whose scheme is not `https` when `network=other`.
2. **Use a hardened HTTP transport:** Configure `http.Transport` with `TLSClientConfig` including certificate pinning or at minimum enforce system CA verification (Go's default `http.Client` does verify TLS certs, but only if HTTPS is actually used).
3. **Remove the `http://` example** from the flag description to avoid normalizing insecure usage.
4. **Consider response signing:** For high-security deployments, sign the `/api/v1/network/nodes` response at the mirror node and verify the signature in the pinger before trusting any endpoint data.

### Proof of Concept
```
# 1. Deploy pinger with:
HIERO_MIRROR_PINGER_NETWORK=other
HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551   # plain HTTP, as documented

# 2. On the same L2 network segment, run ARP spoofing:
arpspoof -i eth0 -t <pinger_ip> <mirror_rest_ip>

# 3. Stand up a rogue HTTP server on the attacker machine responding to
#    GET /api/v1/network/nodes with:
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{
      "ip_address_v4": "<attacker_grpc_ip>",
      "port": 50211
    }]
  }],
  "links": {"next": null}
}

# 4. Run a gRPC listener on <attacker_grpc_ip>:50211 to capture
#    all incoming Hiero transaction RPCs.

# 5. On pinger startup, fetchMirrorNodeNetwork() fetches the rogue response,
#    builds network map = {"<attacker_grpc_ip>:50211": AccountID{0,0,3}},
#    and all subsequent signed transfers are sent to the attacker's gRPC server.
```

### Citations

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/mirror_node_client.go (L36-44)
```go
func buildNetworkFromMirrorNodes(ctx context.Context, cfg config) (map[string]hiero.AccountID, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.mirrorRest), "/")

	var url string
	if strings.HasSuffix(base, "/api/v1") {
		url = base + "/network/nodes"
	} else {
		url = base + "/api/v1/network/nodes"
	}
```

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L79-97)
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
