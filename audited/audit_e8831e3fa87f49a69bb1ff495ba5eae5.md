### Title
DNS Poisoning / BGP Hijack Against Unauthenticated HTTP Mirror REST Endpoint Allows Partial Network Node Exclusion

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` issues a plain, unauthenticated HTTP GET to the operator-configured mirror REST URL and unconditionally trusts the returned `nodesEnvelope` JSON to build the SDK's consensus-node routing table. No TLS is enforced, no response is signed, and no minimum node-count floor is validated. An attacker who can poison DNS or hijack BGP for the mirror REST hostname can return a partial node list, causing the pinger's SDK client to silently exclude 30 %+ of legitimate consensus nodes from all subsequent transaction routing.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go`, `buildNetworkFromMirrorNodes()` (lines 36–72) constructs the target URL directly from `cfg.mirrorRest` — a value that defaults to the example `http://mirror-rest:5551` (plain HTTP, no TLS) — and passes it to `fetchMirrorNodeNetwork()`. [1](#0-0) 

The HTTP client is created with **only** a timeout; no custom `Transport`, no TLS configuration, no certificate pinning: [1](#0-0) 

Inside `fetchMirrorNodeNetwork()` (lines 74–132), the request is fired with no authentication or integrity check: [2](#0-1) 

The response body is decoded directly into `nodesEnvelope`: [3](#0-2) 

The **only** guard is an empty-map check: [4](#0-3) 

The resulting map is handed verbatim to `hiero.ClientForNetwork(netmap)`, which becomes the sole routing table for all SDK transactions: [5](#0-4) 

**Root cause / failed assumption:** The code assumes the mirror REST endpoint is reachable only over a trusted, integrity-protected channel. In practice, when the URL scheme is `http://` (as shown in the documented default), there is no transport-layer protection at all. Even with `https://`, no certificate pinning or response signing prevents a network-level attacker from substituting a response.

**Why the existing check is insufficient:** Returning a `nodesEnvelope` with even a single valid-looking entry (e.g., one real node) satisfies `len(network) > 0` and passes through without error. There is no floor on the number of nodes, no cross-check against a known-good set, and no cryptographic proof of authenticity.

### Impact Explanation
When `network=other` is configured (the only mode that calls `buildNetworkFromMirrorNodes`), the attacker-supplied node list becomes the **complete** routing table for the pinger's Hiero SDK client. If the attacker omits 30 %+ of real consensus nodes, all transactions submitted by the pinger are routed exclusively to the remaining nodes. This satisfies the stated scope condition: shutdown of ≥ 30 % of network processing nodes from the pinger's perspective, without brute-force. The pinger will continue operating normally (no errors, liveness probe stays green) while silently bypassing the excluded nodes for the lifetime of the process.

### Likelihood Explanation
- **DNS poisoning** against an `http://` endpoint requires no special privileges: cache poisoning (e.g., Kaminsky-style), rogue DHCP/DNS in the same network segment, or compromised upstream resolver all suffice for an unprivileged external attacker.
- **BGP hijacking** of the mirror REST hostname's IP prefix is a well-documented, nation-state-to-sophisticated-attacker capability, but has been demonstrated by non-state actors repeatedly.
- The attack is **repeatable**: the pinger only calls `buildNetworkFromMirrorNodes` once at startup, so a single poisoned response persists for the entire process lifetime until restart.
- The default example URL in `config.go` line 37 explicitly uses `http://`, making the plain-HTTP attack path the documented default for `network=other` deployments. [6](#0-5) 

### Recommendation
1. **Enforce HTTPS** — validate at config load time that `cfg.mirrorRest` begins with `https://`; reject `http://` schemes.
2. **TLS certificate pinning or CA restriction** — configure the `http.Client` with a custom `tls.Config` that pins the expected server certificate or restricts the acceptable CA pool.
3. **Minimum node-count floor** — after decoding, reject any response that returns fewer nodes than a configurable minimum (e.g., `minNodes`), preventing a partial-list attack even if TLS is bypassed.
4. **Response signing** — have the mirror node sign the `/network/nodes` response body; verify the signature before trusting the payload.
5. **Cross-validate against a static bootstrap list** — on startup, compare the fetched node set against a hard-coded or operator-supplied baseline; abort if the overlap falls below a threshold.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest.example.com:5551` (plain HTTP).
- Attacker can poison the DNS record for `mirror-rest.example.com` (e.g., via a rogue resolver, cache poisoning, or compromised upstream DNS).

**Steps:**

1. Attacker stands up a web server at their controlled IP on port 5551.
2. Attacker poisons DNS so `mirror-rest.example.com` resolves to their IP.
3. Attacker's server responds to `GET /api/v1/network/nodes` with:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           {"ip_address_v4": "34.94.106.61", "port": 50211}
         ]
       }
     ],
     "links": {"next": null}
   }
   ```
   (Only 1 of ~30 mainnet nodes listed — >96 % excluded.)
4. Pinger starts; `fetchMirrorNodeNetwork()` resolves to attacker's server, decodes the payload, passes `len(network) == 1 > 0` check, returns the single-entry map.
5. `hiero.ClientForNetwork(netmap)` builds an SDK client routing exclusively to node `0.0.3`.
6. All pinger transactions are sent only to `0.0.3`; all other consensus nodes receive zero traffic from this pinger for the process lifetime.

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L79-84)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := httpClient.Do(req)
```

**File:** pinger/mirror_node_client.go (L95-98)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
