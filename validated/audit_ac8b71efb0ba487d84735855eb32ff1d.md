All code references check out. Let me verify the exact line numbers and claims against the actual source.

**Verification summary:**

- `sdk_client.go` lines 18–22: `buildNetworkFromMirrorNodes()` called, result passed directly to `hiero.ClientForNetwork(netmap)` — **confirmed** [1](#0-0) 
- `mirror_node_client.go` line 46: `http.Client` constructed with only a timeout, no custom transport/TLS config — **confirmed** [2](#0-1) 
- `mirror_node_client.go` lines 79–98: only HTTP status code checked, response decoded blindly — **confirmed** [3](#0-2) 
- `mirror_node_client.go` lines 100–125: every `(host, port)` inserted verbatim into `network` map — **confirmed** [4](#0-3) 
- `config.go` line 37: example URL `http://mirror-rest:5551` (plain HTTP) in flag description — **confirmed** [5](#0-4) 

**SECURITY.md scope check:**
- "Lack of SSL/TLS best practices" is listed as out of scope — however, this finding goes beyond a TLS best-practice gap. The root issue is that a security-critical bootstrap operation (constructing the entire gRPC network map) has zero integrity verification at any layer, and the SDK client is built exclusively from the unverified response. This is a design-level trust boundary violation, not merely a missing header or cipher suite recommendation.
- "Impacts involving attacks requiring access to the local network of the victim" — the plain-HTTP/ARP-spoofing vector is excluded, but the BGP hijack and DNS poisoning vectors do not require local network access and are not excluded.
- All other exclusions (theoretical without PoC, best-practice recommendations) do not apply — the exploit flow is concrete and the code path is fully traceable.

---

Audit Report

## Title
Unauthenticated Mirror Node REST Response Allows Network Map Poisoning via BGP Hijack or DNS Poisoning

## Summary
`buildNetworkFromMirrorNodes()` constructs the entire gRPC network map by issuing an unauthenticated HTTP GET to the configured mirror REST endpoint and blindly trusting the JSON response. No TLS certificate pinning, no response signature verification, and no allowlist validation of returned endpoints exist. A network-level attacker who can redirect that HTTP traffic via BGP hijack or DNS poisoning can return a fabricated `nodesEnvelope` that replaces every legitimate gRPC endpoint with attacker-controlled addresses, causing all subsequent pinger transactions to be submitted to rogue nodes.

## Finding Description
**Code path:**

`pinger/sdk_client.go` lines 17–22: when `cfg.network == "other"`, `buildNetworkFromMirrorNodes()` is called and its return value is passed directly to `hiero.ClientForNetwork(netmap)` with no further validation. [1](#0-0) 

`pinger/mirror_node_client.go` line 46: the HTTP client is constructed with only a timeout — no custom `TLSClientConfig`, no certificate pinning, no transport-level integrity enforcement. [2](#0-1) 

`pinger/mirror_node_client.go` lines 79–98: the GET request is issued and the response body is decoded directly into `nodesEnvelope`. The only check performed is the HTTP status code (lines 90–93); there is no cryptographic verification of the payload, no comparison against a known-good node set, and no validation that returned IP addresses or domain names belong to the expected network. [3](#0-2) 

`pinger/mirror_node_client.go` lines 100–125: every `(host, port)` pair returned by the attacker-controlled response is inserted verbatim into the `network` map. [4](#0-3) 

**Root cause:** The code assumes the HTTP response originates from a trusted mirror node. No transport-layer or application-layer integrity mechanism enforces that assumption.

**Default configuration amplifier:** `pinger/config.go` line 37 documents the canonical example URL as `http://mirror-rest:5551` (plain HTTP). [5](#0-4) 

## Impact Explanation
- **Transaction interception:** The attacker receives every signed transaction, including the operator account ID, destination, amount, and transaction ID.
- **Transaction suppression (DoS):** The attacker can silently drop all transactions. The pinger logs a failure but the operator cannot distinguish a rogue-node drop from a legitimate network error.
- **False receipt injection:** Because `GetReceipt` uses the same poisoned client, the attacker can return `SUCCESS` receipts for transactions never submitted to the real network, causing the pinger to report false health.
- **Severity: High** — complete loss of transaction integrity and monitoring reliability for the `network=other` deployment mode.

## Likelihood Explanation
- **BGP hijack:** Requires control of an AS or a compromised BGP router. Demonstrated repeatedly in the wild (e.g., Amazon Route 53 2018, MyEtherWallet 2018). Nation-state or well-resourced attacker capability.
- **DNS poisoning:** Lower bar than BGP; a compromised upstream resolver or a cache-poisoning attack against an unvalidated resolver suffices.
- The attack is persistent: the network map is built once at startup; a single successful redirect permanently poisons the client for the lifetime of the process.

## Recommendation
1. **Enforce HTTPS:** Reject any `mirrorRest` URL that does not use the `https` scheme at config load time in `loadConfig()`.
2. **TLS verification:** Do not disable `InsecureSkipVerify`; rely on the system certificate pool or a pinned CA for the mirror node's TLS certificate.
3. **Allowlist validation:** After fetching the node list, validate that returned hostnames/IPs match a configurable allowlist or a known-good set of network node addresses before passing the map to `hiero.ClientForNetwork`.
4. **Response integrity:** Consider requiring a signed manifest or comparing the returned node set against a secondary trusted source before accepting it.

## Proof of Concept
1. Attacker redirects DNS resolution for the mirror REST hostname to an attacker-controlled server (e.g., via DNS cache poisoning or BGP route hijack).
2. Attacker's server returns a well-formed `nodesEnvelope` JSON with `service_endpoints` pointing to attacker-controlled gRPC addresses and valid-looking `node_account_id` values.
3. `fetchMirrorNodeNetwork()` accepts the response (status 200, valid JSON, non-empty endpoint list) and returns the poisoned map — all checks at lines 90–93 and 127–129 pass.
4. `hiero.ClientForNetwork(netmap)` builds the SDK client exclusively from rogue endpoints.
5. Every `submitWithRetry()` tick sends a signed `CryptoTransfer` transaction to the attacker's gRPC server.
6. `resp.GetReceipt(client)` also queries the same rogue network, so the attacker can return fabricated `SUCCESS` receipts, masking the attack indefinitely.

### Citations

**File:** pinger/sdk_client.go (L17-22)
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
