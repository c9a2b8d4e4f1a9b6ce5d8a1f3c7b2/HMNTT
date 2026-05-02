### Title
Insufficient Node Count Validation Allows Poisoned Mirror REST Response to Reduce Pinger's Network View to 1–2 Nodes

### Summary
`fetchMirrorNodeNetwork` in `pinger/mirror_node_client.go` only rejects an empty node map (`len(network) == 0`), with no minimum node count check. When `network=other`, the pinger fetches its consensus node list over a plain HTTP connection to an operator-configured mirror REST URL. An attacker who can MITM that HTTP connection (or compromise the mirror REST service) can return a response containing only 1–2 nodes; the map passes validation and is handed directly to `hiero.ClientForNetwork(netmap)`, causing the SDK to route all subsequent transactions exclusively to those nodes and silently ignore 30%+ of the real network.

### Finding Description

**Code path:**

`pinger/sdk_client.go` lines 18–22 — when `cfg.network == "other"`, `buildNetworkFromMirrorNodes` is called and its result is passed without any size check to `hiero.ClientForNetwork(netmap)`:

```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
// ...
client = hiero.ClientForNetwork(netmap)
``` [1](#0-0) 

`pinger/mirror_node_client.go` lines 127–129 — the **only** guard against a bad response is a zero-length check:

```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
``` [2](#0-1) 

A response containing exactly 1 or 2 nodes produces `len(network) >= 1`, passes this check, and is returned as a valid network map.

**Root cause:** The failed assumption is that the mirror REST endpoint is trusted and will always return a representative set of nodes. There is no minimum node count, no comparison against an expected baseline, and no TLS enforcement on the `mirrorRest` URL. [3](#0-2) 

The `mirrorRest` URL is operator-supplied and may use plain `http://`: [4](#0-3) 

### Impact Explanation
Once `hiero.ClientForNetwork(netmap)` is initialized with a 1–2 node map, the Hiero SDK routes every `TransferTransaction.Execute()` call exclusively to those nodes for the entire lifetime of the process (client is built once at startup and never refreshed). [5](#0-4) [6](#0-5) 

The pinger becomes blind to 30%+ of the real consensus network: failures, latency spikes, or outages on the omitted nodes go undetected, producing false-healthy liveness signals. If the attacker controls the 1–2 injected nodes, they also observe every transaction the pinger submits (including operator account IDs and keys in flight over the gRPC channel).

### Likelihood Explanation
**Preconditions:** `network=other` must be configured (required for private/custom networks, which is the exact use-case this code path serves). The mirror REST URL must use HTTP rather than HTTPS — common in internal Kubernetes deployments where TLS termination is handled at the ingress layer and internal service-to-service traffic is plain HTTP. The attacker needs network-level MITM capability (ARP spoofing on the same subnet, DNS poisoning, a compromised sidecar/proxy, or a rogue mirror REST service). No credentials or privileged access to the pinger process are required.

**Repeatability:** The attack only needs to succeed once — at pinger startup — because the client is never rebuilt. A brief MITM window at boot is sufficient for a persistent effect.

### Recommendation
1. **Enforce a minimum node count** in `fetchMirrorNodeNetwork`: reject any response with fewer than a configurable threshold (e.g., 3 nodes by default) and treat it as a retryable error.
2. **Validate TLS** for the mirror REST URL: reject `http://` URLs in `loadConfig` when `network=other`, or at minimum log a prominent warning and document the risk.
3. **Periodically refresh** the network map rather than building the client once at startup, so a transient MITM cannot cause a permanent degraded state.
4. Optionally, pin an expected set of node account IDs and reject any response that omits more than X% of them.

### Proof of Concept
1. Deploy pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (plain HTTP, internal cluster).
2. At pinger startup, intercept the HTTP GET to `http://mirror-rest:5551/api/v1/network/nodes` (e.g., via ARP spoofing or a rogue DNS entry pointing `mirror-rest` to an attacker-controlled host).
3. Return a valid JSON response containing only 1–2 `nodeEntry` objects with attacker-controlled `service_endpoints`.
4. `fetchMirrorNodeNetwork` returns a map of size 1–2; `len(network) == 0` is false, so no error is raised.
5. `hiero.ClientForNetwork(netmap)` is called with the sparse map; all subsequent `TransferTransaction.Execute()` calls in `submitWithRetry` are routed exclusively to the attacker's nodes.
6. The pinger reports healthy for the entire network while 30%+ of real nodes are never contacted. [7](#0-6) [8](#0-7)

### Citations

**File:** pinger/sdk_client.go (L12-46)
```go
func newClient(cfg config) (*hiero.Client, error) {
	var client *hiero.Client
	var err error

	switch cfg.network {
	case "other":
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
	return client, nil
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/transfer.go (L33-33)
```go
		resp, err := cryptoTransfer.Execute(client)
```

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```
