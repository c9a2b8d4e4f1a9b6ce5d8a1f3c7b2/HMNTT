### Title
Unauthenticated HTTP Network Bootstrap Allows MitM Injection of Attacker-Controlled gRPC Endpoints

### Summary
When `network=other` is configured, `buildNetworkFromMirrorNodes()` fetches consensus node endpoints over a plain HTTP connection with no TLS enforcement, no certificate pinning, and no response integrity verification. An attacker with a network-adjacent position can intercept the HTTP response and inject a crafted `nodesEnvelope` JSON payload, causing the Hiero SDK client to be initialized with attacker-controlled gRPC endpoints. All subsequent `CryptoTransfer` transactions are then routed exclusively to the attacker's node for the lifetime of the process.

### Finding Description

**Code path:**

- `pinger/config.go` line 37: `cfg.mirrorRest` is operator-supplied (e.g., `http://mirror-rest:5551`). No HTTPS scheme is enforced.
- `pinger/mirror_node_client.go` line 46: `httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}` — a plain `net/http` client with no TLS configuration, no custom `Transport`, and no certificate pinning.
- `pinger/mirror_node_client.go` lines 79–98: An HTTP GET is issued to `cfg.mirrorRest + /api/v1/network/nodes`. The response body is decoded directly into `nodesEnvelope` with `json.NewDecoder(resp.Body).Decode(&payload)`. No HMAC, signature, or any integrity check is performed on the payload.
- `pinger/mirror_node_client.go` lines 100–124: The `network` map is populated entirely from the decoded JSON — `host:port` strings mapped to `AccountID` values — with no allowlist of legitimate IPs, domains, or ports.
- `pinger/sdk_client.go` line 22: `hiero.ClientForNetwork(netmap)` initializes the SDK client with the attacker-controlled map.
- `pinger/main.go` line 63 / `pinger/transfer.go` line 33: `submitWithRetry()` calls `cryptoTransfer.Execute(client)` in a loop for the entire process lifetime using this poisoned client.

**Root cause:** The code assumes the HTTP response from `cfg.mirrorRest` is trustworthy. There is no transport security requirement and no response authentication.

**Why existing checks are insufficient:**

| Check | Location | Bypass |
|---|---|---|
| HTTP status 2xx | line 90–93 | Attacker returns `200 OK` |
| Non-empty `NodeAccountID` | line 103 | Attacker supplies `"0.0.3"` |
| `AccountIDFromString` parse | line 107–110 | Any valid `shard.realm.num` string passes |
| Non-empty host and non-zero port | line 118–120 | Attacker supplies their own IP and port |
| Non-empty network map | line 127–129 | Attacker supplies ≥1 endpoint |

A single crafted JSON body such as:
```json
{"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"attacker.ip","port":50211}]}],"links":{"next":null}}
```
passes every check and results in a network map containing only the attacker's endpoint.

### Impact Explanation

The SDK client is initialized once at startup (`main.go` line 41) and reused for every tick. Once poisoned, **all** `CryptoTransfer` transactions for the entire process lifetime are sent to the attacker's gRPC server. The attacker can:

1. **Silently drop** all transactions — the pinger's monitoring purpose is defeated without any visible error (the attacker's server can return a plausible gRPC error or simply time out).
2. **Observe** transaction content including `TransactionID`, amounts, and account IDs in plaintext gRPC.
3. **Replay** captured signed transactions to a legitimate node at a time of the attacker's choosing.

The operator private key is never exposed (it signs locally), but transaction integrity and delivery guarantees are completely broken. Severity: **High** — complete loss of transaction routing integrity for the `network=other` deployment mode.

### Likelihood Explanation

**Preconditions:**
- `HIERO_MIRROR_PINGER_NETWORK=other` must be set (non-default for public networks, but the explicit use-case for private/custom deployments).
- `HIERO_MIRROR_PINGER_REST` must use `http://` — the documented example (`http://mirror-rest:5551`) is plaintext.
- Attacker must be network-adjacent: same Kubernetes cluster node, same subnet, or able to perform DNS spoofing/ARP poisoning against the internal hostname `mirror-rest`.

In a Kubernetes or Docker Compose deployment (the intended environment given the `Dockerfile` and internal hostname), a compromised co-tenant pod, a rogue DNS entry, or ARP poisoning on the pod network are all realistic without any privileges on the pinger container itself. The attack is **repeatable** on every process restart and requires no ongoing access once the poisoned client is initialized.

### Recommendation

1. **Enforce HTTPS**: Validate that `cfg.mirrorRest` begins with `https://` at startup in `loadConfig()`, and reject `http://` schemes with a fatal error.
2. **Pin or verify the TLS certificate**: Use a custom `http.Transport` with a pinned CA or leaf certificate for the mirror REST endpoint.
3. **Validate response content**: Maintain a configurable allowlist of expected `NodeAccountID` values and/or IP ranges; reject any response containing endpoints outside the allowlist.
4. **Re-fetch periodically with integrity checks**: If the network map must be refreshed, re-validate against the previous known-good map and alert on unexpected changes rather than silently replacing it.

### Proof of Concept

**Environment:** `network=other`, `mirrorRest=http://mirror-rest:5551` (default example), attacker controls DNS for `mirror-rest` or is ARP-adjacent on the pod network.

**Steps:**

1. Attacker stands up a listener:
   - HTTP server on port 5551 serving the crafted JSON at `GET /api/v1/network/nodes`.
   - gRPC server on port 50211 that accepts `CryptoTransfer` requests and drops/logs them.

2. Attacker redirects `mirror-rest` to their HTTP server (DNS poisoning, ARP spoofing, or `/etc/hosts` injection in a compromised sidecar).

3. Pinger starts (or restarts). `buildNetworkFromMirrorNodes()` issues `GET http://mirror-rest:5551/api/v1/network/nodes`.

4. Attacker's HTTP server responds with:
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [{"ip_address_v4": "192.168.1.100", "port": 50211}]
     }],
     "links": {"next": null}
   }
   ```

5. All checks in `fetchMirrorNodeNetwork()` pass. `hiero.ClientForNetwork({"192.168.1.100:50211": AccountID{0,0,3}})` is called.

6. Every subsequent `cryptoTransfer.Execute(client)` in `submitWithRetry()` sends the signed transaction to `192.168.1.100:50211` (attacker's node) instead of any legitimate consensus node.

7. Attacker observes, drops, or replays all transactions. The pinger reports success or timeout depending on what the attacker's gRPC server returns. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
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

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```
