### Title
Unvalidated `node_account_id` Shard/Realm Allows Mirror Node to Poison SDK Network Map and Halt All Transactions

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` blindly trusts the `node_account_id` strings returned by the configured mirror REST endpoint. An attacker who controls that endpoint (via MITM, DNS poisoning, or a compromised server) can return account IDs with arbitrary shard/realm values (e.g., `1.2.3`). These parse successfully through `hiero.AccountIDFromString`, are inserted into the SDK network map without any shard/realm validation, and cause every subsequent transaction to be rejected by the real consensus nodes — a complete pinger shutdown.

### Finding Description
**Code path:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 102–124.

```
for _, n := range payload.Nodes {
    if n.NodeAccountID == "" {          // only guard: empty string
        continue
    }
    nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
    if err != nil {                     // only guard: parse failure
        continue
    }
    // ← NO shard/realm check here
    for _, ep := range n.ServiceEndpoints {
        ...
        network[addr] = nodeAccountId  // poisoned ID stored
    }
}
```

`hiero.AccountIDFromString("1.2.3")` succeeds — it is syntactically valid. The resulting `AccountID{Shard:1, Realm:2, Num:3}` is stored in the network map and passed directly to `hiero.ClientForNetwork(netmap)` (`sdk_client.go` line 22). The Hiero SDK embeds the node account ID from this map into the `nodeAccountID` field of every submitted transaction. The real consensus node (whose actual account ID is `0.0.3`) rejects the transaction because the embedded node account ID does not match its own identity. All nodes in the map can be poisoned simultaneously, causing 100% transaction failure.

**Root cause:** The code assumes the mirror node is trusted and performs no cross-validation of shard/realm against the expected network (shard 0, realm 0). The two existing guards (`== ""` and parse error) are both bypassed by a well-formed but wrong-shard string.

### Impact Explanation
Every `cryptoTransfer.Execute(client)` call in `transfer.go` will fail for all retry attempts. The pinger stops producing successful heartbeats, `/tmp/alive` stops being updated, and the liveness probe fails — causing the pod to be killed and restarted in a loop. From a monitoring/alerting perspective this is indistinguishable from a real network outage, which is the stated critical impact scope: "total network shutdown" (of the pinger's view of the network). Severity: **High** — full loss of pinger functionality with no self-recovery until the mirror endpoint is restored.

### Likelihood Explanation
The attack requires the ability to control or intercept the mirror REST endpoint configured via `HIERO_MIRROR_PINGER_REST`. The HTTP client is created with only a timeout and no TLS pinning or certificate enforcement:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

If the operator configures an `http://` (plaintext) URL — common in internal/Kubernetes deployments — any network-adjacent attacker (same cluster, same subnet, or with ARP/DNS control) can perform a trivial MITM. Even with `https://`, a compromised internal CA or DNS record is sufficient. No credentials or privileged access to the pinger process itself are required.

### Recommendation
After parsing each `node_account_id`, validate that shard and realm match the expected values for the target network (both `0` for all current Hiero networks):

```go
nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
if err != nil {
    continue
}
if nodeAccountId.Shard != 0 || nodeAccountId.Realm != 0 {
    log.Printf("skipping node with unexpected shard/realm: %s", n.NodeAccountID)
    continue
}
```

Additionally, enforce HTTPS with proper certificate validation for the mirror REST endpoint, and consider adding a minimum-node-count threshold so that a response with suspiciously few nodes is rejected rather than accepted.

### Proof of Concept
1. Stand up a mock HTTP server that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [{
    "node_account_id": "1.2.3",
    "service_endpoints": [{"ip_address_v4": "34.94.106.61", "port": 50211}]
  }],
  "links": {"next": null}
}
```
2. Configure the pinger: `HIERO_MIRROR_PINGER_NETWORK=other`, `HIERO_MIRROR_PINGER_REST=http://<mock-server>`.
3. Start the pinger with valid operator credentials.
4. Observe: `buildNetworkFromMirrorNodes` returns `{"34.94.106.61:50211": AccountID{1,2,3}}` with no error.
5. The SDK client is initialized with this map. Every `Execute` call embeds node account ID `1.2.3` in the transaction body.
6. The real consensus node at `34.94.106.61:50211` (whose account ID is `0.0.3`) rejects the transaction.
7. All retry attempts exhaust; pinger logs `all attempts failed` on every tick; liveness probe eventually kills the pod. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L102-124)
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
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```
