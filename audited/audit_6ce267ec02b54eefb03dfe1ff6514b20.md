### Title
Unauthenticated HTTP Mirror REST Endpoint Allows Network-Map Poisoning via DNS/BGP Hijack in `fetchMirrorNodeNetwork()`

### Summary
`buildNetworkFromMirrorNodes()` in `pinger/mirror_node_client.go` constructs a plain `http.Client` with no TLS configuration and issues an unauthenticated HTTP GET to the mirror REST endpoint. The returned `nodesEnvelope` JSON is accepted without any integrity, signature, or IP-range validation. An attacker who can redirect the HTTP request (via DNS poisoning or BGP hijacking) can return a crafted envelope whose `ServiceEndpoints` all resolve to unreachable addresses, causing `hiero.ClientForNetwork()` to be seeded with a dead network map and every subsequent gossip transaction to silently fail.

### Finding Description
**Exact code path:**

- `pinger/mirror_node_client.go`, `buildNetworkFromMirrorNodes()`, line 46:
  ```go
  httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
  ```
  A vanilla `http.Client` is created with no custom `Transport`, no TLS pinning, and no enforcement that the scheme must be `https://`.

- The default Helm value (`charts/hedera-mirror-pinger/values.yaml`, line 19) sets:
  ```yaml
  HIERO_MIRROR_PINGER_REST: "http://{{ .Release.Name }}-restjava:80"
  ```
  Plain HTTP is the shipped default.

- `fetchMirrorNodeNetwork()` (lines 74–131) issues the GET, JSON-decodes the body into `nodesEnvelope`, and iterates `payload.Nodes`. For each entry it accepts any non-empty `DomainName` or `IPAddressV4` with a non-zero `Port` (lines 113–124). No allowlist, no IP-range check, no response signature.

- The only guard is `len(network) == 0` (line 127). A crafted response that contains syntactically valid `node_account_id` values (e.g. `"0.0.3"`) paired with unreachable IPs (e.g. `192.0.2.1`) passes this check and returns a non-empty map.

- `sdk_client.go` line 22 feeds the poisoned map directly into `hiero.ClientForNetwork(netmap)`, which the SDK uses as the exclusive set of consensus nodes for all subsequent gRPC calls.

**Root cause / failed assumption:** The code assumes the HTTP response originates from a trusted mirror node. There is no transport-layer authentication (TLS with certificate verification), no application-layer integrity check (e.g. signed response body), and no semantic validation of the returned endpoints.

### Impact Explanation
Once `hiero.ClientForNetwork()` is initialised with a dead network map, every `submitWithRetry()` call in the main ticker loop (`main.go` lines 63–68) will fail to reach any consensus node. The pinger's gossip transactions silently fail on every tick. Because the client is constructed once at startup (`sdk_client.go` line 22) and never refreshed, the disruption persists for the entire lifetime of the process. This constitutes a complete, persistent denial-of-service of the pinger's transaction-submission function without any error that would distinguish a network-map poisoning from a genuine network outage.

### Likelihood Explanation
The attack requires the ability to redirect the HTTP request before it reaches the real mirror REST service. Two realistic paths exist:

1. **DNS poisoning (moderate feasibility):** If `mirrorRest` is configured as an external hostname (common in non-Kubernetes or hybrid deployments), a network-positioned attacker can poison the DNS resolver used by the pinger pod. No credentials to the target system are required.
2. **BGP hijacking (lower feasibility, higher impact):** An attacker controlling upstream BGP routing can announce a more-specific prefix covering the mirror REST server's IP, redirecting traffic at the network layer. This is a known, documented attack class used against public infrastructure.

For the default Kubernetes deployment the target is an in-cluster DNS name, which raises the bar; however, any deployment that points `HIERO_MIRROR_PINGER_REST` at an external HTTP URL is directly exposed. The attack is repeatable on every pinger restart or pod reschedule.

### Recommendation
1. **Enforce HTTPS:** Reject any `mirrorRest` URL whose scheme is not `https` at config-load time (`config.go`). Update the Helm default to `https://`.
2. **Enable TLS certificate verification:** The default Go `http.Client` verifies TLS certificates when HTTPS is used; simply switching the scheme activates this protection.
3. **Add response integrity validation:** Validate that returned `IPAddressV4` values fall within expected CIDR ranges or match a configured allowlist before populating the network map.
4. **Periodic refresh with change detection:** Re-fetch the network map periodically and alert/abort if the returned endpoints differ significantly from the previous set, limiting the blast radius of a poisoning attack.
5. **Consider certificate pinning** for the mirror REST endpoint in high-security deployments.

### Proof of Concept
**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<external-or-dns-resolvable-host>/`
- Attacker can poison the DNS record for `<external-or-dns-resolvable-host>` or BGP-hijack its IP prefix.

**Steps:**
1. Stand up a malicious HTTP server that responds to `GET /api/v1/network/nodes` with:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           {"ip_address_v4": "192.0.2.1", "port": 50211}
         ]
       }
     ],
     "links": {"next": null}
   }
   ```
2. Redirect DNS resolution (or BGP route) for the mirror REST hostname to the malicious server.
3. Start (or restart) the pinger. `buildNetworkFromMirrorNodes()` fetches the crafted response; `len(network) == 1` so no error is returned.
4. `hiero.ClientForNetwork({"192.0.2.1:50211": AccountID{0,0,3}})` is called.
5. Every subsequent `submitWithRetry()` call times out attempting to reach `192.0.2.1:50211`; all gossip transactions fail for the lifetime of the process. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
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

**File:** charts/hedera-mirror-pinger/values.yaml (L19-19)
```yaml
  HIERO_MIRROR_PINGER_REST: "http://{{ .Release.Name }}-restjava:80"
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
