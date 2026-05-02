### Title
Unauthenticated Mirror Node HTTP Response Enables Network Map Poisoning to Redirect Signed Transactions

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches the Hedera node list over a plain, unauthenticated HTTP connection with no response integrity verification. An attacker with a network-level man-in-the-middle position can substitute a crafted `nodesEnvelope` payload, causing the pinger to build a network map pointing entirely to attacker-controlled gRPC endpoints. Every subsequent signed transaction is then submitted to the attacker rather than the legitimate Hedera network, without any approval from the operator/signer.

### Finding Description
**Exact code path:**

- `pinger/mirror_node_client.go`, `buildNetworkFromMirrorNodes()` (lines 36–72) constructs the URL from `cfg.mirrorRest` and calls `fetchMirrorNodeNetwork()`.
- `fetchMirrorNodeNetwork()` (lines 74–132) creates an `http.Client` with only a timeout (line 46 of `mirror_node_client.go`, instantiated at the call site in `buildNetworkFromMirrorNodes` line 46): `httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}`. No `TLSClientConfig`, no transport-level pinning.
- Lines 79–88: a plain `http.NewRequestWithContext` GET is issued; the only check on the response is the HTTP status code (lines 90–93).
- Lines 95–98: the body is decoded directly into `nodesEnvelope` with no HMAC, no signature, no certificate pinning, no field-level validation beyond JSON well-formedness.
- Lines 100–124: the decoded `payload.Nodes` entries are iterated; each `ServiceEndpoint.DomainName` / `IPAddressV4` + `Port` is accepted verbatim and inserted into the `network` map.
- `sdk_client.go` line 22: `hiero.ClientForNetwork(netmap)` builds the SDK client from this map; line 45: `client.SetOperator(opID, opKey)` attaches the operator's private key.
- `transfer.go` line 33: `cryptoTransfer.Execute(client)` signs and submits every periodic transfer to whatever endpoints are in that map.

**Root cause:** The `http.Client` is constructed with no transport security beyond a timeout. The documented and example value for `HIERO_MIRROR_PINGER_REST` is `http://mirror-rest:5551` (plain HTTP, config.go line 37). Even for HTTPS deployments, there is no certificate pinning and no cryptographic verification of the response body. The failed assumption is that the mirror node REST endpoint is implicitly trusted because it is "internal."

**Why existing checks are insufficient:**
- HTTP 2xx status check (lines 90–93): trivially satisfied by the attacker's spoofed server.
- JSON decode (lines 96–98): only ensures syntactic validity; attacker provides valid JSON.
- `NodeAccountID` parse (lines 107–109): only validates format (e.g., `"0.0.3"`); attacker supplies legitimate-looking account IDs paired with their own endpoints.
- Empty-network guard (lines 127–129): attacker returns ≥1 valid entry, bypassing this check.

### Impact Explanation
All signed `CryptoTransfer` transactions are delivered to attacker-controlled gRPC endpoints instead of the Hedera network. The attacker receives fully signed, valid Hedera transactions. Consequences include: (1) complete silent failure of the pinger's monitoring function — the operator believes transfers are being submitted while none reach the real network; (2) the attacker collects signed transactions and can attempt replay or analysis; (3) the operator's HBAR balance is not debited (transactions never execute on-chain), but the monitoring/alerting purpose of the pinger is entirely subverted. Severity is **High** for integrity and availability of the pinger service.

### Likelihood Explanation
The precondition is a network-level MITM position between the pinger container and the mirror REST endpoint. For the documented plain-HTTP deployment (`http://mirror-rest:5551`), this is achievable via ARP spoofing or rogue DHCP on the same L2 segment, DNS poisoning of the `mirror-rest` hostname, or compromise of any in-path network device — all feasible for an attacker who has gained any foothold on the cluster network (e.g., a compromised co-tenant pod in Kubernetes). For externally-reachable HTTP mirror URLs, BGP hijacking or DNS cache poisoning suffices. No credentials or privileged access to the pinger host are required. The attack is repeatable on every pinger restart (the network map is fetched once at startup).

### Recommendation
1. **Enforce HTTPS**: Reject any `mirrorRest` URL that does not use the `https://` scheme at config validation time (`config.go`, after line 133).
2. **Certificate pinning or CA restriction**: Configure the `http.Transport` with a restricted `tls.Config` that pins the expected server certificate or limits acceptable CAs.
3. **Response integrity**: If the mirror node operator can publish a signed manifest (e.g., a JWS/JWT-wrapped node list), verify the signature before consuming the payload.
4. **Endpoint allowlist**: After decoding, validate that returned IP addresses and domain names fall within a configured allowlist of known Hedera node addresses before populating the network map.

### Proof of Concept
**Preconditions:** Attacker controls DNS resolution for `mirror-rest` (or has ARP/DHCP MITM on the pinger's network). Pinger is configured with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.

**Steps:**
1. Stand up a malicious HTTP server on attacker-controlled host at port 5551. Serve the following on `GET /api/v1/network/nodes`:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           { "ip_address_v4": "<attacker-ip>", "port": 50211 }
         ]
       }
     ],
     "links": { "next": null }
   }
   ```
2. Poison DNS so `mirror-rest` resolves to `<attacker-ip>`, or perform ARP spoofing to intercept the HTTP connection.
3. Start (or restart) the pinger. `buildNetworkFromMirrorNodes` fetches the poisoned response; `fetchMirrorNodeNetwork` decodes it without any integrity check and returns `{"<attacker-ip>:50211": AccountID{0,0,3}}`.
4. `hiero.ClientForNetwork` builds the SDK client with this map. `client.SetOperator` attaches the real operator key.
5. On every ticker tick, `submitWithRetry` → `cryptoTransfer.Execute(client)` signs a transfer and sends it over gRPC to `<attacker-ip>:50211`.
6. The attacker's gRPC server receives fully signed Hedera `CryptoTransfer` transactions. The real Hedera network receives nothing.