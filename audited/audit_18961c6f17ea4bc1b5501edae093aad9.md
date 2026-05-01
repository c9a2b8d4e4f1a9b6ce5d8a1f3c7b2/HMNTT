Now I have the full picture. Let me analyze the complete attack chain.

### Title
Unauthenticated Mirror Node Response Allows Full Network Map Hijacking via Rogue Service Endpoints

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches consensus node addresses over an unauthenticated, potentially plaintext HTTP connection and builds the entire gRPC network map from the response with no validation of the returned IP addresses or domain names. A network-level attacker who can intercept or control the mirror node REST endpoint — requiring no credentials to the pinger itself — can inject attacker-owned addresses, causing every subsequent Hiero transaction to be routed to rogue nodes that apply non-standard fees, drop transactions, or harvest signed transaction data.

### Finding Description

**Exact code path:**

`pinger/sdk_client.go` line 18–22: when `cfg.network == "other"`, `buildNetworkFromMirrorNodes()` is called and its result is passed directly to `hiero.ClientForNetwork(netmap)` with no further checks. [1](#0-0) 

`pinger/mirror_node_client.go` lines 74–132: `fetchMirrorNodeNetwork()` issues a plain `http.Client` GET, JSON-decodes the response body into a `nodesEnvelope`, and for each `serviceEndpoint` entry uses `ep.DomainName` or `ep.IPAddressV4` verbatim as the gRPC host, then calls `net.JoinHostPort(host, port)` to build the map key. [2](#0-1) 

**Root cause — failed assumption:** The code assumes the mirror node REST response is authoritative and trustworthy. There is no cryptographic verification of the response, no TLS enforcement on the HTTP client, no comparison of returned node account IDs against a known-good set, and no IP/domain allowlist.

**Existing checks and why they are insufficient:**

- Line 103: `if n.NodeAccountID == ""` — rejects empty strings only; a value like `"0.0.999"` (non-existent node) passes. [3](#0-2) 
- Line 107: `hiero.AccountIDFromString(n.NodeAccountID)` — validates format (`shard.realm.num`) only, not membership in the real consensus committee. [4](#0-3) 
- Line 118: `if host == "" || ep.Port == 0` — rejects blank/zero only; any attacker IP with a non-zero port passes. [5](#0-4) 
- Line 127: `if len(network) == 0` — only ensures at least one entry exists; a map of entirely rogue entries satisfies this. [6](#0-5) 

**Exploit flow:**

The `mirrorRest` config value is documented with an `http://` example and there is no code-level enforcement of HTTPS. [7](#0-6) 

The `http.Client` is constructed with only a timeout — no custom `Transport` with TLS settings, no certificate pinning. [8](#0-7) 

A MITM attacker on the network path intercepts the plaintext HTTP GET to `/api/v1/network/nodes`, replaces the body with a crafted `nodesEnvelope` whose `service_endpoints` all point to attacker-controlled gRPC servers, and the pinger builds its entire `ClientForNetwork` map from those addresses.

### Impact Explanation

Every Hiero `CryptoTransfer` the pinger submits — signed with the real operator private key — is sent to rogue gRPC nodes. Those nodes can: (1) charge arbitrary transaction fees deviating from network consensus, (2) silently drop transactions while returning fake receipts, (3) record all signed transaction bytes (operator key usage, amounts, destination accounts). Because the network map is set once at startup and never re-validated, the compromise persists for the entire lifetime of the process. Severity: **High**.

### Likelihood Explanation

The attack requires only network-level access between the pinger pod and the mirror REST service — achievable via ARP spoofing on a shared L2 segment, DNS poisoning, a compromised internal load balancer, or a malicious mirror node operator. No credentials to the pinger are needed. The `http://` scheme is the documented example and is common in internal Kubernetes deployments. The attack is fully repeatable and silent.

### Recommendation

1. **Enforce HTTPS** — validate that `cfg.mirrorRest` starts with `https://` at config load time; reject `http://` URLs.
2. **Pin or verify the TLS certificate** — use a custom `http.Transport` with a configured `RootCAs` pool or explicit certificate fingerprint check.
3. **Validate returned node account IDs** — compare parsed `NodeAccountID` values against a configurable allowlist of known consensus node IDs (e.g., `0.0.3`–`0.0.28` for mainnet).
4. **Validate returned IP addresses** — reject RFC 1918 addresses, loopback, and addresses outside expected CIDR ranges unless explicitly configured.
5. **Re-fetch and diff periodically** — if the network map changes dramatically between polls, log and alert rather than silently adopting the new map.

### Proof of Concept

```
# Preconditions:
# - Pinger deployed with HIERO_MIRROR_PINGER_NETWORK=other
# - HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551  (plaintext HTTP)
# - Attacker has network access between pinger and mirror-rest (e.g., same K8s namespace)

# Step 1: Stand up a rogue gRPC server on attacker machine (192.168.1.100:50211)
#         that accepts CryptoTransfer and returns SUCCESS with a manipulated fee.

# Step 2: Stand up a rogue HTTP server returning:
cat > rogue_nodes.json << 'EOF'
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "ip_address_v4": "192.168.1.100", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
EOF

# Step 3: MITM or DNS-poison mirror-rest:5551 to point to rogue HTTP server.
#         On a shared network: arpspoof -i eth0 -t <pinger-ip> <mirror-rest-ip>

# Step 4: Pinger starts, calls fetchMirrorNodeNetwork(), receives rogue_nodes.json,
#         builds network map: {"192.168.1.100:50211": AccountID{0,0,3}}
#         hiero.ClientForNetwork(map) routes all transactions to 192.168.1.100:50211.

# Step 5: All subsequent CryptoTransfer calls from the pinger hit the rogue node.
#         Rogue node applies fee = 10x normal, returns TRANSACTION_EXPIRED, or
#         logs the full signed transaction bytes for later analysis.
```

### Citations

**File:** pinger/sdk_client.go (L17-23)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)

```

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L103-105)
```go
		if n.NodeAccountID == "" {
			continue
		}
```

**File:** pinger/mirror_node_client.go (L107-110)
```go
		nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
		if err != nil {
			continue
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
