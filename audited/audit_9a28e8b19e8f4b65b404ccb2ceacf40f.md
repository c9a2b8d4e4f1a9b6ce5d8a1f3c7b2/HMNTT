### Title
Unauthenticated Mirror REST Network-Map Poisoning Enables Silent Transaction Suppression in `submitWithRetry()`

### Summary
When `network=other`, `buildNetworkFromMirrorNodes()` fetches the consensus-node address book from an unauthenticated, plain-HTTP mirror REST endpoint and blindly trusts every IP/port/account-ID tuple it returns. A network-adjacent attacker who can MITM or spoof that HTTP response can replace all node endpoints with attacker-controlled gRPC servers. Because `Execute(client)` and `GetReceipt(client)` in `submitWithRetry()` both use the same poisoned client, the attacker's fake server can return a synthetic `SUCCESS` receipt, causing the pinger to log "transfer success" while no transaction ever reaches the real Hedera network.

### Finding Description

**Code path:**

`pinger/sdk_client.go` `newClient()` (line 18) calls `buildNetworkFromMirrorNodes()` only when `cfg.network == "other"`. That function (`pinger/mirror_node_client.go` lines 36–72) constructs a bare `http.Client` with no TLS certificate pinning, no HMAC, no signature verification:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}  // line 46
```

`fetchMirrorNodeNetwork()` (lines 74–132) issues a plain GET, decodes the JSON body, and maps every `(host, port)` → `node_account_id` tuple into the network map with no authenticity checks:

```go
addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
network[addr] = nodeAccountId   // line 122-123
```

The only guards are:
- `n.NodeAccountID == ""` (line 103) — syntactic, not semantic
- `host == "" || ep.Port == 0` (line 118) — presence check only
- `len(network) == 0` (line 127) — non-empty check only

None of these verify that the returned endpoints correspond to real Hedera consensus nodes.

`hiero.ClientForNetwork(netmap)` (`sdk_client.go` line 22) then creates a client whose entire node set is attacker-controlled.

In `submitWithRetry()` (`transfer.go` lines 33–42):

```go
resp, err := cryptoTransfer.Execute(client)   // line 33 — gRPC to attacker's server
if err == nil {
    receipt, rerr := resp.GetReceipt(client)  // line 35 — gRPC to attacker's server
    if rerr == nil {
        log.Printf("transfer success: ...")   // line 37 — false positive
        return nil
    }
}
```

Both `Execute` and `GetReceipt` use the same poisoned client. The attacker's fake gRPC server returns a well-formed `TransactionResponse` (no error) and a `TransactionGetReceiptResponse` with `status = SUCCESS`. The pinger returns `nil` and logs success. No transaction was ever gossiped.

**Root cause:** The mirror REST URL is operator-supplied and may be plain HTTP (the documented example in `config.go` line 37 is `http://mirror-rest:5551`). The fetched node list is treated as a trusted authority with no cryptographic binding to the real Hedera address book.

### Impact Explanation
The pinger's sole purpose is to detect gossip failures. A poisoned network map defeats this entirely: every tick the pinger reports success while submitting nothing to the real network. Monitoring dashboards and alerting pipelines that rely on pinger success metrics become blind. An attacker can suppress all pinger alerts during a real network outage or targeted attack, preventing operators from detecting the incident. Severity: **High** — complete loss of the monitoring signal the pinger is designed to provide.

### Likelihood Explanation
Preconditions for a network-adjacent attacker in a Kubernetes/container environment (the deployment target, evidenced by `/tmp/alive` and `/tmp/ready` liveness/readiness probes in `main.go` lines 36, 47):
- ARP poisoning, rogue DHCP, or DNS spoofing within the pod network — achievable from any compromised pod in the same namespace
- OR compromise of the mirror REST service itself (single point of trust with no verification)

The attack is persistent (network map is built once at startup, `newClient()` is called once in `main.go` line 41), repeatable, and requires no credentials. Standard MITM tooling suffices.

### Recommendation
1. **Enforce HTTPS** for `mirrorRest` and reject `http://` URLs at config validation time (`config.go`).
2. **Pin the CA or certificate** of the mirror REST endpoint using a custom `tls.Config` in the `http.Client` constructed in `buildNetworkFromMirrorNodes()`.
3. **Cross-validate returned endpoints** against a static allowlist of known-good node account IDs and/or IP ranges supplied out-of-band (e.g., embedded in the container image or a Kubernetes Secret).
4. **Periodically refresh** the network map and detect sudden wholesale replacement of all endpoints as an anomaly.
5. Consider using `hiero.ClientForName()` (which uses a hardcoded, SDK-embedded address book) even for private networks, or use `SetNetworkFromAddressBook` with a cryptographically signed address book.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`
- Attacker has network-adjacent access (e.g., compromised pod in same Kubernetes namespace)

**Steps:**

1. Attacker runs a fake mirror REST HTTP server returning:
```json
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{
      "ip_address_v4": "<attacker-ip>",
      "port": 50211
    }]
  }],
  "links": {"next": null}
}
```

2. Attacker poisons DNS or ARP so `mirror-rest:5551` resolves to `<attacker-ip>`.

3. Attacker runs a fake gRPC server on `<attacker-ip>:50211` that:
   - Accepts any `CryptoTransfer` RPC and returns `ResponseCodeEnum.OK`
   - Accepts any `TransactionGetReceipt` RPC and returns `status = SUCCESS`

4. Pinger starts (or restarts). `buildNetworkFromMirrorNodes()` fetches the poisoned node list. `hiero.ClientForNetwork()` builds a client pointing entirely to `<attacker-ip>:50211`.

5. Every tick: `Execute(client)` → fake gRPC OK; `GetReceipt(client)` → fake `SUCCESS`. Pinger logs `transfer success: status=SUCCESS`. No transaction reaches the real Hedera network.

6. Operators see green pinger metrics while the real network may be completely unreachable.