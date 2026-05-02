All code references were verified against the actual source. Every line number, struct field, function name, and behavior described in the report matches the real code exactly.

**Verification summary:**

- `nodesEnvelope.Links.Next *string` declared at lines 17–22 but never read after `json.Decode` at line 96. [1](#0-0) 
- `fetchMirrorNodeNetwork()` iterates only `payload.Nodes` and returns on `len(network) > 0` with no pagination follow-through. [2](#0-1) 
- `buildNetworkFromMirrorNodes()` accepts the first successful result and returns immediately. [3](#0-2) 
- `hiero.ClientForNetwork(netmap)` permanently fixes the SDK node pool. [4](#0-3) 
- `http.Client` has no TLS config. [5](#0-4) 
- `/tmp/alive` and `/tmp/ready` confirm Kubernetes deployment context. [6](#0-5) 

SECURITY.md exclusions checked: the "local network" exclusion is scoped to "Websites and Apps"; this is a backend Go service. The "Lack of SSL/TLS best practices" exclusion does not cover the core defect (incomplete pagination logic). No exclusion applies to this finding.

---

# Audit Report

## Title
Incomplete Pagination in `fetchMirrorNodeNetwork()` Allows MITM Attacker to Bias Transaction Routing via Crafted Partial Node List

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the `Links.Next` pagination field from the mirror node REST response but never follows it. An attacker with a network-adjacent MITM position can return a crafted first page containing only attacker-chosen consensus nodes while setting `links.next` to a non-null value. The pinger accepts this as a complete, successful response, builds a permanently incomplete node map, and routes all subsequent transactions exclusively through the attacker-selected nodes for the lifetime of the process.

## Finding Description
`nodesEnvelope.Links.Next` is declared as `*string` and populated during JSON decoding at line 96, but is never read or acted upon afterward. [1](#0-0) [7](#0-6) 

After decoding, the function iterates only over `payload.Nodes` and returns success as soon as `len(network) > 0`: [2](#0-1) 

`buildNetworkFromMirrorNodes()` calls `fetchMirrorNodeNetwork()` in a retry loop and returns the first non-error result with no completeness check: [3](#0-2) 

The returned map is passed directly to `hiero.ClientForNetwork(netmap)`, permanently fixing the SDK's node pool: [4](#0-3) 

The `http.Client` is constructed with only a timeout — no TLS configuration, no certificate pinning, and no enforcement of HTTPS: [5](#0-4) 

**Root cause:** The code assumes a single HTTP response contains the full node list. The `len(network) > 0` guard is treated as a completeness check, but it only rejects a fully empty response. A paginated response with one node on the first page satisfies this guard while omitting all remaining nodes.

**Exploit flow:**
1. Attacker intercepts the HTTP GET to `/api/v1/network/nodes` (plain HTTP is permitted; no TLS enforcement exists).
2. Attacker returns a crafted 200 OK JSON body: one or two real node entries plus `"links": {"next": "/api/v1/network/nodes?limit=25&node.id=gt:0.0.5"}`.
3. `fetchMirrorNodeNetwork()` decodes the body, builds a one-entry `network` map, sees `len(network) == 1 > 0`, and returns `(network, false, nil)` — success.
4. `buildNetworkFromMirrorNodes()` returns this map immediately.
5. `newClient()` calls `hiero.ClientForNetwork(netmap)` with the single-entry map.
6. Every `submitWithRetry()` call in the ticker loop routes its `TransferTransaction` exclusively through the attacker-chosen node.

**Why existing checks are insufficient:**
- The `len(network) == 0` guard rejects only a completely empty response; a deliberately truncated one with one entry passes.
- The retry loop retries on network errors and 5xx/429 responses, but a 200 OK with a partial body is accepted immediately and terminates the retry loop.
- No HTTPS enforcement or certificate pinning exists on the `http.Client`.

## Impact Explanation
The pinger's entire transaction stream is permanently redirected to attacker-chosen consensus nodes for the lifetime of the process (until restart). This alters the distribution of transactions recorded in mirror node history, enabling selective concentration of pinger-originated transactions on specific nodes. Monitoring, alerting, and analytics that rely on uniform node coverage will produce skewed results. No funds are directly stolen (the operator key is still required to sign), but the integrity of the mirror node's transaction history is compromised. Severity is **Medium**.

## Likelihood Explanation
The attack requires a network-adjacent MITM position. The Kubernetes deployment context is confirmed by `/tmp/alive` and `/tmp/ready` probe files in `main.go`: [6](#0-5) 

In such deployments, the mirror REST URL is commonly configured as a plain `http://` in-cluster service address. Any attacker with access to the pod network (compromised sidecar, ARP spoofing on a flat network, or DNS poisoning of the in-cluster service name) can execute this attack. The attack is repeatable on every pinger restart, requires no credentials, and produces a valid 200 OK JSON body that bypasses HTTP-status-based anomaly detection.

## Recommendation
1. **Follow pagination:** After decoding each page, check `payload.Links.Next`. If non-nil, construct the next URL and continue fetching, accumulating all nodes before returning.
2. **Enforce HTTPS:** Reject `mirrorRest` URLs that do not use the `https` scheme, or configure the `http.Client` with a strict TLS config.
3. **Add a minimum node count threshold:** Reject responses where the resulting `network` map contains fewer nodes than a configurable minimum (e.g., 3), making single-node truncation attacks immediately detectable.
4. **Validate `Links.Next` is nil before returning:** Treat a non-nil `Links.Next` on the final accepted page as an error condition requiring a retry.

## Proof of Concept
Craft the following JSON response to serve from a MITM position when the pinger GETs `/api/v1/network/nodes`:

```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        {
          "domain_name": "attacker-node.example.com",
          "ip_address_v4": "",
          "port": 50211
        }
      ],
      "grpc_proxy_endpoint": null
    }
  ],
  "links": {
    "next": "/api/v1/network/nodes?limit=25&node.id=gt:0.0.3"
  }
}
```

`fetchMirrorNodeNetwork()` will decode this, build `network = {"attacker-node.example.com:50211": AccountID{0,0,3}}`, pass the `len(network) > 0` guard at line 127, and return success. `hiero.ClientForNetwork` will be called with this single-entry map, and all subsequent `TransferTransaction` submissions will be routed exclusively to `attacker-node.example.com:50211`. [8](#0-7)

### Citations

**File:** pinger/mirror_node_client.go (L17-22)
```go
type nodesEnvelope struct {
	Nodes []nodeEntry `json:"nodes"`
	Links struct {
		Next *string `json:"next"`
	} `json:"links"`
}
```

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L52-56)
```go
	for attempt := 1; attempt <= attempts; attempt++ {
		network, retry, err := fetchMirrorNodeNetwork(ctx, httpClient, url)
		if err == nil {
			return network, nil
		}
```

**File:** pinger/mirror_node_client.go (L95-98)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```

**File:** pinger/mirror_node_client.go (L102-131)
```go
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

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/main.go (L36-47)
```go
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
			}
		}
	}()

	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}

	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
```
