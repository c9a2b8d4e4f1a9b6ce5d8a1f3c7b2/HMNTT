### Title
Unauthenticated Mirror Node Response Poisons Consensus Node Network Map, Routing Signed Transactions to Attacker Infrastructure

### Summary
`fetchMirrorNodeNetwork()` fetches consensus node gRPC endpoints over plain HTTP with no response authentication, signature verification, or endpoint allowlisting. When `network=other`, the entire `hiero.Client` network map is built exclusively from this unverified response. An attacker who can control or intercept the mirror node HTTP response can substitute all `ServiceEndpoints` with attacker-controlled addresses, causing every operator-signed `CryptoTransfer` to be submitted to attacker infrastructure.

### Finding Description

**Exact code path:**

1. `config.go` line 37: `mirrorRest` is set from `HIERO_MIRROR_PINGER_REST`. The documented example is `http://mirror-rest:5551` — a plaintext HTTP URL with no TLS.

2. `sdk_client.go` lines 17–22: When `cfg.network == "other"`, `buildNetworkFromMirrorNodes` is called and its result is passed directly to `hiero.ClientForNetwork(netmap)` with no further validation.

3. `mirror_node_client.go` lines 46–46: The HTTP client is constructed as bare `&http.Client{Timeout: cfg.mirrorNodeClientTimeout}` — no TLS pinning, no mutual auth, no custom transport.

4. `mirror_node_client.go` lines 84–93: The HTTP response is accepted if the status code is 2xx. No authentication header, no HMAC, no signature is checked.

5. `mirror_node_client.go` lines 102–124: Every `ServiceEndpoints` entry from the response is accepted verbatim. The only checks are that `NodeAccountID` is non-empty and parseable, and that `host`/`port` are non-empty. Any IP address or domain name is accepted without restriction.

6. `mirror_node_client.go` line 122–123: `addr := net.JoinHostPort(host, ...)` → `network[addr] = nodeAccountId` — attacker-supplied addresses are inserted directly into the network map.

7. `transfer.go` lines 29–33: `hiero.NewTransferTransaction().Execute(client)` submits the operator-signed transaction to whichever gRPC endpoints are in the network map — now entirely attacker-controlled.

**Root cause:** The function assumes the HTTP response from the mirror node is authoritative and trustworthy. There is no mechanism to verify that the returned `ServiceEndpoints` correspond to legitimate Hedera consensus nodes.

**Failed assumption:** The code assumes the configured mirror node URL is a trusted, integrity-protected source of consensus node topology. In practice, the transport is plaintext HTTP (per the documented example), making the response trivially interceptable and modifiable.

**Why existing checks are insufficient:**
- Lines 90–93: Only validates HTTP status code — an attacker's server returns `200 OK`.
- Lines 103–105: Only checks `NodeAccountID` is non-empty — attacker supplies valid-looking account IDs like `0.0.3`.
- Lines 118–119: Only checks host and port are non-empty — attacker supplies their own IP/domain and port.
- No IP allowlist, no domain allowlist, no cross-check against a known-good node set, no cryptographic verification of any kind.

### Impact Explanation

The attacker's gRPC server receives fully operator-signed `CryptoTransfer` transactions. These transactions are cryptographically valid on the real Hedera network. The attacker can:

1. **Replay on the real network:** Submit the received signed transactions to legitimate Hedera consensus nodes, causing real fund transfers. Each pinger tick produces a new transaction ID (account + timestamp), so Hedera's deduplication does not prevent replay of distinct ticks.
2. **Retry amplification:** By returning gRPC errors, the attacker causes `submitWithRetry` (transfer.go lines 23–57) to generate additional signed transactions per tick (up to `cfg.maxRetries + 1` = 11 by default), multiplying the number of replayable signed transactions.
3. **Exfiltration:** The attacker observes all transaction details including operator account ID, destination account, and amount.

The operator's funds are drained while the pinger logs only gRPC failures, with no indication that signed transactions are being harvested.

### Likelihood Explanation

The precondition is `network=other`, which is the custom-network deployment path. The attack surface is:

- **MITM on plaintext HTTP:** The documented example URL `http://mirror-rest:5551` uses HTTP. Any attacker with network-layer access (same Kubernetes cluster, same VPC, ARP spoofing on a shared segment, compromised sidecar) can intercept and rewrite the response. This requires no special privileges on the pinger host itself.
- **DNS poisoning:** If `mirrorRest` uses a hostname, DNS cache poisoning redirects the pinger to the attacker's server.
- **Compromised mirror node:** If the mirror node itself is compromised (it is a separate service, not a consensus node), the attacker gains full control of the response.

The attack is repeatable on every pinger restart (the network map is built once at startup in `newClient`) and requires no interaction from the operator after initial deployment.

### Recommendation

1. **Enforce HTTPS with certificate verification:** Reject `mirrorRest` URLs that do not use `https://` at config load time (`config.go`). Do not allow the operator to disable TLS verification.
2. **Allowlist consensus node endpoints:** Maintain a configurable allowlist of known-good consensus node IP ranges or domain suffixes. Reject any `ServiceEndpoints` entry that does not match.
3. **Cross-validate against a static bootstrap list:** For `network=other`, require a static list of at least one known-good consensus node endpoint in config. Reject the mirror node response if it contains no overlap with the bootstrap list.
4. **Pin the mirror node TLS certificate or CA:** Use a custom `tls.Config` with a pinned CA or leaf certificate for the mirror node HTTP client, preventing MITM even if the CA store is compromised.
5. **Validate `NodeAccountID` shard/realm/num ranges:** Reject node account IDs outside the expected range for the target network as a defense-in-depth measure.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (plaintext HTTP, as documented).
- Attacker has network-layer access to intercept traffic between the pinger and `mirror-rest:5551` (e.g., same Kubernetes namespace, ARP spoofing, or compromised DNS).

**Steps:**

1. Attacker stands up a rogue HTTP server on their controlled host (e.g., `attacker-host:8080`) and a rogue gRPC server on `attacker-host:50211`.

2. Rogue HTTP server responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "ip_address_v4": "<attacker-host>", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
```

3. Attacker intercepts the pinger's HTTP request to `mirror-rest:5551` (via ARP spoofing, iptables REDIRECT, or DNS poisoning) and returns the above response.

4. `fetchMirrorNodeNetwork()` (lines 100–124) builds `network = {"<attacker-host>:50211": AccountID{0,0,3}}` and returns it.

5. `hiero.ClientForNetwork(netmap)` (sdk_client.go line 22) creates a client pointing exclusively to `attacker-host:50211`.

6. On each ticker tick, `submitWithRetry` (transfer.go line 33) calls `cryptoTransfer.Execute(client)`, which signs the transaction with the operator's private key and sends it via gRPC to `attacker-host:50211`.

7. Attacker's gRPC server logs the fully signed `CryptoTransfer` protobuf, then submits it to a real Hedera consensus node. The transaction is accepted because the signature is valid.

8. Attacker returns a gRPC error to the pinger, triggering up to 10 retries (each with a new transaction ID), harvesting up to 11 signed transactions per tick interval.

**Result:** Operator funds are transferred on the real network on every pinger tick. The pinger logs only `transfer failed` errors, giving no indication of the actual fund drain.