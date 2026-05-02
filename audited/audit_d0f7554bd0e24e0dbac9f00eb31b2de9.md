### Title
Unauthenticated HTTP Mirror-Node Response Allows Network-Map Poisoning via Injected `service_endpoints`

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` makes a plain, unauthenticated HTTP GET to `cfg.mirrorRest` and blindly trusts the JSON response to build the gRPC network map. Any attacker who can control or intercept that HTTP response — via MITM on a plaintext connection, DNS hijacking, or a compromised mirror node — can inject arbitrary `service_endpoints` values into the recognized JSON fields. Go's `json.NewDecoder().Decode()` silently discards unknown fields while faithfully deserializing the recognized ones, so a crafted response passes decoding without error and poisons the `netmap` fed to `hiero.ClientForNetwork()`.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–131.

```
// line 84-98
resp, err := httpClient.Do(req)          // plain HTTP, no TLS enforcement
...
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}
```

The only guard before decoding is an HTTP status-code range check (lines 90–93). There is no:
- TLS/HTTPS enforcement on `cfg.mirrorRest`
- `Content-Type` header validation
- Response signature or HMAC verification
- Allowlist of permitted IP addresses, domain names, or port numbers

After decoding, lines 102–124 iterate `payload.Nodes` and build `network[addr] = nodeAccountId` directly from the attacker-supplied `service_endpoints`:

```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" { host = strings.TrimSpace(ep.IPAddressV4) }
    if host == "" || ep.Port == 0 { continue }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId          // attacker-controlled addr
}
```

The only filtering is that `host` must be non-empty and `port` must be non-zero — trivially satisfied by any attacker-supplied value.

**Root cause / failed assumption:** The code assumes the HTTP endpoint at `cfg.mirrorRest` is trustworthy and returns authentic node topology. No transport security or response integrity mechanism enforces this assumption.

**Go JSON silent-ignore behavior:** Go's `encoding/json` decoder ignores unknown fields by default. An attacker can include arbitrary extra fields (which are silently dropped) alongside the recognized `nodes[].service_endpoints` field containing malicious values. The decoder returns `nil` error, and the poisoned data flows directly into the network map.

**Exploit flow:**
1. Attacker intercepts or controls the HTTP response from `cfg.mirrorRest/api/v1/network/nodes`.
2. Returns a crafted JSON body with `service_endpoints` pointing to attacker-controlled gRPC hosts/ports; unknown extra fields are silently ignored.
3. `fetchMirrorNodeNetwork()` decodes without error and returns the poisoned map.
4. `buildNetworkFromMirrorNodes()` returns it to `newClient()` (sdk_client.go line 18–22).
5. `hiero.ClientForNetwork(netmap)` builds a client targeting attacker-controlled nodes.
6. All subsequent pinger transactions are submitted to those nodes.

### Impact Explanation
The pinger's entire gRPC node set is replaced with attacker-controlled endpoints. Consequences:
- **Monitoring bypass:** The attacker's nodes can return fake success responses; the pinger reports healthy while the real network is not being probed.
- **Transaction interception:** The attacker observes all submitted transactions, including timing, amounts, and operator account patterns.
- **Denial of service:** Returning unreachable endpoints causes all pinger transactions to fail silently, defeating the health-check purpose.
- **Operator key exposure risk:** While the private key is never transmitted, repeated failed/replayed gRPC calls to a malicious node may leak metadata exploitable in further attacks.

### Likelihood Explanation
- **`network=other` is the only affected mode**, but it is the mode explicitly designed for custom/private deployments — exactly where a self-hosted mirror node (potentially less hardened) is used.
- If `cfg.mirrorRest` is an `http://` URL (no TLS), any on-path network attacker (same LAN, rogue router, cloud VPC peer) can MITM without any credentials.
- DNS hijacking of the mirror node hostname requires no privileged access to the pinger deployment itself.
- The attack is repeatable: `buildNetworkFromMirrorNodes` is called once at startup; a single poisoned response is sufficient.

### Recommendation
1. **Enforce HTTPS:** Reject `cfg.mirrorRest` URLs that do not use the `https` scheme, or configure TLS with certificate verification on the `http.Client`.
2. **Validate decoded endpoints:** After decoding, reject entries whose `IPAddressV4` or `DomainName` resolve outside an expected CIDR/domain allowlist, and reject ports outside the expected gRPC range (e.g., 50211).
3. **Use `json.Decoder.DisallowUnknownFields()`:** While not a security fix on its own, it makes the parser strict and surfaces unexpected response shapes.
4. **Pin or verify node identity:** Cross-check returned `node_account_id` values against a locally configured expected set before adding them to the network map.

### Proof of Concept
```
# 1. Stand up a malicious HTTP server returning crafted JSON:
cat > fake_mirror.json << 'EOF'
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "unexpected_field": "ignored by Go decoder",
      "service_endpoints": [
        { "ip_address_v4": "192.0.2.1", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
EOF
python3 -m http.server 8080   # serve fake_mirror.json at /api/v1/network/nodes

# 2. Run pinger pointed at the malicious server:
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://127.0.0.1:8080 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# 3. Observe: pinger builds netmap with 192.0.2.1:50211 (attacker-controlled),
#    all gRPC calls go to that address, real network is never contacted.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L17-34)
```go
type nodesEnvelope struct {
	Nodes []nodeEntry `json:"nodes"`
	Links struct {
		Next *string `json:"next"`
	} `json:"links"`
}

type nodeEntry struct {
	NodeAccountID     string            `json:"node_account_id"`
	ServiceEndpoints  []serviceEndpoint `json:"service_endpoints"`
	GrpcProxyEndpoint *serviceEndpoint  `json:"grpc_proxy_endpoint"`
}

type serviceEndpoint struct {
	DomainName  string `json:"domain_name"`
	IPAddressV4 string `json:"ip_address_v4"`
	Port        int    `json:"port"`
}
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

**File:** pinger/mirror_node_client.go (L100-125)
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
