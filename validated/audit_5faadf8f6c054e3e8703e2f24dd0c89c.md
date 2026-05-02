The code is confirmed exactly as described. Let me verify all required checks against the actual source.

**Check 1 — File/function/line references:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 113–124 match exactly. [1](#0-0) 

**Check 2 — Root cause:** The only guard is `host == ""` at line 118. `"0.0.0.0"` is a non-empty string and passes unconditionally. [2](#0-1) 

**Check 3 — Exploit flow:** The poisoned map is passed directly to `hiero.ClientForNetwork(netmap)` at `sdk_client.go` line 22 with no further filtering. [3](#0-2) 

**Check 4 — Plain HTTP confirmed:** The Helm chart default sets `HIERO_MIRROR_PINGER_REST: "http://{{ .Release.Name }}-restjava:80"` — no TLS. [4](#0-3) 

All four required checks pass. No Security.MD exists in the repository to establish out-of-scope exclusions.

---

# Audit Report

## Title
`0.0.0.0` IP Address Bypasses Empty-String Check in `fetchMirrorNodeNetwork`, Redirecting gRPC Traffic to Localhost

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` validates service endpoint hosts only by checking for an empty string. The reserved address `"0.0.0.0"` is non-empty and passes this check, causing it to be inserted into the SDK network map. On Linux, a `connect()` to `0.0.0.0` is treated as `127.0.0.1`, silently redirecting all consensus-node gRPC traffic — including signed transactions — to localhost.

## Finding Description
**File:** `pinger/mirror_node_client.go`
**Function:** `fetchMirrorNodeNetwork()`
**Lines:** 113–124

```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)   // "0.0.0.0" is non-empty
    }
    if host == "" || ep.Port == 0 {                // sole guard; "0.0.0.0" passes
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId                  // "0.0.0.0:<port>" inserted
}
``` [1](#0-0) 

The returned map is passed without further filtering to `hiero.ClientForNetwork(netmap)`: [3](#0-2) 

**Root cause:** The code assumes any non-empty, non-zero-port pair is a valid routable address. It never validates whether the IP is a reserved or special address (`0.0.0.0`, `127.x`, RFC-1918 ranges, etc.).

## Impact Explanation
The pinger submits real on-chain `CryptoTransfer` transactions every tick (default: 10,000 tinybar, configurable via `HIERO_MIRROR_PINGER_AMOUNT_TINYBAR`). [5](#0-4) 

Redirecting gRPC to a localhost listener allows an attacker to:
- Observe every signed `CryptoTransfer`, including serialised transaction bytes and the operator's signature.
- Silently drop transactions, causing the pinger to report false node-health failures and masking real outages.
- In a shared-node Kubernetes environment, replay captured signed transactions against the real network.

## Likelihood Explanation
The mirror node REST URL is fetched over plain HTTP. The Helm chart default is:

```yaml
HIERO_MIRROR_PINGER_REST: "http://{{ .Release.Name }}-restjava:80"
``` [4](#0-3) 

No TLS is enforced. An attacker who can compromise or impersonate the mirror node (realistic in a self-hosted deployment), or perform DNS/ARP spoofing on the cluster network (realistic in a multi-tenant Kubernetes environment), can inject this payload with zero authentication required. The attack is repeatable on every pinger restart or network-refresh cycle.

## Recommendation
Add an explicit blocklist (or allowlist) for reserved/special IP addresses before inserting an endpoint into the network map. At minimum, reject addresses that parse to the unspecified address (`0.0.0.0`), loopback (`127.x.x.x`), and optionally RFC-1918 private ranges. Example guard to add after line 116:

```go
if ip := net.ParseIP(host); ip != nil {
    if ip.IsUnspecified() || ip.IsLoopback() {
        continue
    }
}
```

Additionally, enforce TLS for the mirror node REST connection (or at minimum validate the server certificate) to prevent HTTP MITM injection of malicious endpoint data.

## Proof of Concept
1. Stand up a gRPC listener on `127.0.0.1:50211` inside the pinger pod.
2. Serve the following JSON from the mirror node REST endpoint (`/api/v1/network/nodes`):
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [{"ip_address_v4": "0.0.0.0", "domain_name": "", "port": 50211}]
     }],
     "links": {"next": null}
   }
   ```
3. Start the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` pointing to the controlled mirror node.
4. `fetchMirrorNodeNetwork` returns `{"0.0.0.0:50211": AccountID{0,0,3}}`.
5. `hiero.ClientForNetwork` opens a gRPC connection to `0.0.0.0:50211`; on Linux this connects to `127.0.0.1:50211`.
6. The localhost listener receives all subsequent signed `CryptoTransfer` transactions.

### Citations

**File:** pinger/mirror_node_client.go (L113-124)
```go
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

**File:** charts/hedera-mirror-pinger/values.yaml (L19-19)
```yaml
  HIERO_MIRROR_PINGER_REST: "http://{{ .Release.Name }}-restjava:80"
```

**File:** pinger/config.go (L44-44)
```go
	amountStr := envOr("HIERO_MIRROR_PINGER_AMOUNT_TINYBAR", "10000")
```
