### Title
Unauthenticated Mirror Node Response Enables Rogue Node Injection via Network-Level MITM

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches the Hiero network topology over a plain, unauthenticated HTTP connection and blindly trusts every field in the returned `nodesEnvelope` JSON — including `NodeAccountID` and `ServiceEndpoints` — without any signature verification, TLS pinning, or allowlist check. A network-level attacker (ARP/DNS/BGP poisoning, rogue DHCP, or compromised network path) who can intercept the GET `/api/v1/network/nodes` response can substitute a crafted payload that maps all gRPC addresses to a single attacker-controlled endpoint and sets every `NodeAccountID` to an attacker-owned account. All subsequent fee-bearing transactions submitted by the pinger are then routed exclusively through that rogue node.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132.

The HTTP client is constructed with no custom transport, no TLS certificate pinning, and no authentication:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
``` [1](#0-0) 

The GET request is issued and the response body is decoded directly into `nodesEnvelope`:

```go
resp, err := httpClient.Do(req)
...
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil { ... }
``` [2](#0-1) 

Every `NodeAccountID` and every `ServiceEndpoint` from the response is accepted verbatim and inserted into the network map:

```go
nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
...
addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
network[addr] = nodeAccountId
``` [3](#0-2) 

This map is then handed directly to `hiero.ClientForNetwork()`, making it the sole routing table for all subsequent transactions: [4](#0-3) 

**Root cause:** The function assumes the HTTP response originates from a trusted mirror node. There is no HMAC, no response signature, no TLS pinning, no IP/account-ID allowlist, and no cross-check against a known-good node set.

**Why every existing check is insufficient:**

| Check | Attacker bypass |
|---|---|
| HTTP status 200–299 | Attacker's server returns `200 OK` |
| `json.Decode` succeeds | Attacker returns syntactically valid JSON |
| `NodeAccountID == ""` | Attacker supplies `"0.0.9999"` (their account) |
| `AccountIDFromString` parse | Any valid `shard.realm.num` string passes |
| `host == "" \|\| ep.Port == 0` | Attacker supplies their IP and port |
| `len(network) == 0` | Attacker returns at least one entry | [5](#0-4) 

### Impact Explanation

Once the rogue network map is installed:

1. **Node fee redirection** — In Hiero, the `node_account_id` embedded in every submitted transaction determines which account receives the node-fee portion of the transaction fee. With the attacker's account as `NodeAccountID`, every tick of the pinger's transfer loop pays node fees to the attacker rather than to a legitimate consensus node, which is outside the protocol's fee-distribution design.
2. **Silent transaction DoS** — The attacker's gRPC endpoint can accept the signed transaction, return a plausible success response, and never forward it to the real network. The pinger logs success while the transfer never executes on-chain.
3. **Transaction privacy** — The attacker observes every transaction's sender, recipient, and amount before it reaches the network.

Severity: **High**. The operator's funds are consumed in fees, intended transfers silently fail, and the pinger's liveness/readiness signals remain green, masking the compromise.

### Likelihood Explanation

**Preconditions:**
- The pinger is deployed with `HIERO_MIRROR_PINGER_NETWORK=other` (the only path that calls `fetchMirrorNodeNetwork`).
- The mirror REST URL uses `http://` (the documented example is `http://mirror-rest:5551`) **or** uses `https://` without certificate pinning.

**Attacker capability required:** Network-level interception — no application credentials needed. Realistic vectors:
- ARP poisoning on the same L2 segment (e.g., a compromised pod in the same Kubernetes node).
- DNS poisoning of the mirror REST hostname.
- BGP route hijacking for internet-facing deployments.
- Rogue DHCP/gateway in a cloud VPC with misconfigured network policies.

All of these are achievable by an attacker with no Hiero account privileges and no access to the pinger's configuration.

**Repeatability:** The attack is persistent for the lifetime of the pinger process because the network map is built once at startup and never refreshed or re-validated. [6](#0-5) 

### Recommendation

1. **Enforce HTTPS with certificate pinning** — Reject any `mirrorRest` URL that does not use `https://` and configure a pinned CA or leaf certificate for the mirror node.
2. **Allowlist valid `NodeAccountID` values** — At startup, load the expected set of consensus node account IDs (e.g., from a hardcoded or operator-supplied list) and reject any `NodeAccountID` not in that set.
3. **Allowlist valid endpoint IP ranges** — Reject `ServiceEndpoints` whose resolved IP addresses fall outside the known consensus-node CIDR ranges.
4. **Add response integrity** — If the mirror node can sign its `/network/nodes` response (e.g., with an Ed25519 key whose public key is pinned in the pinger config), verify the signature before consuming any field.
5. **Periodic re-validation** — If the network map is ever refreshed at runtime, apply the same checks on every refresh, not just at startup.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
- Attacker has L2 or DNS-level access to intercept traffic between the pinger pod and `mirror-rest:5551`.

**Steps:**

1. Attacker stands up a rogue HTTP server on their controlled host (e.g., `192.168.1.99:5551`) and a rogue gRPC server on `192.168.1.99:50211`.

2. Rogue HTTP server responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.9999",
      "service_endpoints": [
        { "ip_address_v4": "192.168.1.99", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
```

3. Attacker poisons DNS so `mirror-rest` resolves to `192.168.1.99`, or performs ARP poisoning to intercept the TCP connection.

4. Pinger starts, calls `fetchMirrorNodeNetwork()`, receives the crafted response, and builds `network = {"192.168.1.99:50211": AccountID{Account:9999}}`.

5. `hiero.ClientForNetwork(network)` installs this as the sole routing table.

6. Every subsequent `cryptoTransfer.Execute(client)` in `submitWithRetry()` sends the signed transaction to `192.168.1.99:50211` with `node_account_id = 0.0.9999`.

7. The rogue gRPC server collects node fees (credited to account `0.0.9999`), optionally returns a fake `OK` receipt, and never forwards the transaction to the real Hiero network.

8. The pinger logs `transfer success` while no real transfer occurs on-chain. [7](#0-6)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L84-98)
```go
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

**File:** pinger/mirror_node_client.go (L102-129)
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
```

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/transfer.go (L29-39)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
		if err == nil {
			receipt, rerr := resp.GetReceipt(client)
			if rerr == nil {
				log.Printf("transfer success: status=%s txID=%s elapsed=%s",
					receipt.Status.String(), resp.TransactionID.String(), time.Since(start))
				return nil
```
