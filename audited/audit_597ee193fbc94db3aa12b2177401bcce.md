### Title
Unauthenticated HTTP Bootstrap Allows BGP-Hijack-Driven Network Partition via Crafted `nodesEnvelope`

### Summary
`buildNetworkFromMirrorNodes()` fetches Hedera node topology over a plain, unauthenticated HTTP connection with no TLS enforcement, no certificate pinning, and no response-integrity verification. An attacker who can redirect IP traffic to the mirror REST endpoint (e.g., via BGP prefix hijack) can return a crafted `nodesEnvelope` whose `service_endpoints` point entirely to attacker-controlled hosts, causing the pinger's Hiero SDK client to be bootstrapped against a fully adversarial network. No privileges on the target system are required.

### Finding Description

**Code path:**

`pinger/mirror_node_client.go`, `buildNetworkFromMirrorNodes()`, lines 36–72, and `fetchMirrorNodeNetwork()`, lines 74–131.

The HTTP client is constructed with no custom transport, no TLS configuration, and no certificate pinning:

```go
// mirror_node_client.go line 46
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

The base URL is taken verbatim from operator-supplied config (`cfg.mirrorRest`), whose documented example is `http://mirror-rest:5551` — plaintext HTTP:

```go
// config.go line 37
flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "... e.g. http://mirror-rest:5551")
```

The response is decoded and every `service_endpoint` entry is trusted unconditionally:

```go
// mirror_node_client.go lines 102–124
for _, n := range payload.Nodes {
    ...
    for _, ep := range n.ServiceEndpoints {
        host := strings.TrimSpace(ep.DomainName)
        if host == "" { host = strings.TrimSpace(ep.IPAddressV4) }
        addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
        network[addr] = nodeAccountId
    }
}
```

The resulting map is passed directly to `hiero.ClientForNetwork(netmap)` in `sdk_client.go` line 22, permanently configuring the SDK client for the lifetime of the pinger process.

**Root cause:** The bootstrap call trusts the HTTP response body as authoritative network topology with no authentication, no TLS enforcement, and no signature or integrity check. The failed assumption is that the network path to `cfg.mirrorRest` is trusted.

**Exploit flow:**
1. Attacker announces a more-specific BGP prefix covering the mirror node REST endpoint's IP.
2. Traffic from the pinger pod is routed to the attacker's server.
3. Attacker's server returns HTTP 200 with a valid JSON `nodesEnvelope` whose `service_endpoints` list attacker-controlled IPs/ports.
4. `fetchMirrorNodeNetwork` passes all existing checks (status 200, valid JSON, non-empty `node_account_id`, non-empty host/port).
5. `hiero.ClientForNetwork(netmap)` is called with the adversarial map.
6. All subsequent Hedera transactions are submitted to attacker-controlled nodes.

**Existing checks and why they are insufficient:**

| Check | Location | Why it fails |
|---|---|---|
| HTTP status 200–299 | line 90–93 | Attacker returns 200 |
| JSON decode | line 96 | Attacker returns valid JSON |
| `NodeAccountID` non-empty | line 103 | Attacker supplies valid account ID strings |
| `host`/`port` non-empty | lines 115–119 | Attacker supplies valid endpoints |
| No TLS/cert check | — | None exists |
| No response signature | — | None exists |

### Impact Explanation
The pinger's entire Hedera network view is replaced with attacker-controlled endpoints for the lifetime of the process. Consequences include: all submitted transactions go to adversarial nodes (complete network partition from the legitimate Hedera network); transaction content (including operator key usage patterns) is exposed to the attacker; liveness/readiness probes continue to pass while the pinger silently operates on a fake network; monitoring and alerting that depend on successful transaction submission are blinded.

### Likelihood Explanation
BGP hijacking requires no privileges on the target system — only control of a BGP-speaking router or an upstream AS willing to propagate a more-specific prefix announcement. This has been demonstrated repeatedly in the wild (e.g., Amazon Route 53 BGP hijack 2018, MyEtherWallet). The attack is further simplified because the documented and default example URL uses plaintext HTTP (`http://mirror-rest:5551`), eliminating even the partial protection that TLS would provide. The attack is repeatable on every pinger restart and requires no interaction from the operator.

### Recommendation
1. **Enforce HTTPS** for `cfg.mirrorRest`; reject any URL whose scheme is not `https` at config validation time (`config.go`, `loadConfig()`).
2. **Pin the TLS certificate or CA** for the mirror REST endpoint using a custom `http.Transport` with a restricted `tls.Config.RootCAs` pool.
3. **Verify response integrity**: require the mirror node to sign the `nodesEnvelope` (e.g., with an Ed25519 key whose public key is baked into the pinger config), and reject any response that does not carry a valid signature.
4. **Allowlist returned IPs/hostnames**: validate that every `IPAddressV4` or `DomainName` in the response falls within an operator-configured allowlist before adding it to the network map.
5. As a defense-in-depth measure, re-fetch and diff the topology periodically and alert on unexpected changes rather than silently replacing the network map.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<mirror-rest-ip>:5551`.
- Attacker controls a BGP router that can announce `<mirror-rest-ip>/32` (more specific than the legitimate prefix).

**Steps:**

1. Stand up an attacker HTTP server on the hijacked IP that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{
      "ip_address_v4": "198.51.100.1",
      "domain_name": "",
      "port": 50211
    }]
  }],
  "links": {"next": null}
}
```
where `198.51.100.1` is an attacker-controlled gRPC server.

2. Announce the BGP prefix `/32` for `<mirror-rest-ip>` from the attacker's AS.

3. Start (or restart) the pinger. `buildNetworkFromMirrorNodes()` fetches from the attacker's server, all checks pass, and `hiero.ClientForNetwork` is called with `{"198.51.100.1:50211": AccountID{0,0,3}}`.

4. Observe that all subsequent Hedera transactions are submitted to `198.51.100.1:50211` (attacker-controlled), not to any legitimate Hedera node.