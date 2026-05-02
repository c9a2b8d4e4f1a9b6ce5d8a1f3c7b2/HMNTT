### Title
SSRF via Unvalidated `ip_address_v4` / `domain_name` Fields in `fetchMirrorNodeNetwork()`

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches node service endpoints from a mirror REST API and passes them directly to `hiero.ClientForNetwork()` without any validation of the returned IP addresses or hostnames. An attacker who can control or intercept the mirror REST response (e.g., via MITM on a plain-HTTP endpoint or a compromised mirror node) can inject arbitrary addresses — including RFC-1918 ranges, link-local addresses like `169.254.169.254`, or loopback — causing the Hiero SDK's gRPC client to establish connections to internal infrastructure instead of legitimate consensus nodes.

### Finding Description
**Exact code path:**

In `pinger/mirror_node_client.go` lines 113–124:

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

**Root cause:** The only guards are `host == ""` and `ep.Port == 0`. There is no:
- IP address range validation (no block of RFC-1918, link-local `169.254.0.0/16`, loopback `127.0.0.0/8`, or other reserved ranges)
- Domain name allowlist or DNS rebinding protection
- TLS/certificate pinning on the mirror REST HTTP call itself

The `cfg.mirrorRest` example in `config.go` line 37 is `http://mirror-rest:5551` — plain HTTP — making the connection trivially interceptable by any network-adjacent attacker.

**Exploit flow:**
1. Attacker positions themselves as MITM on the plain-HTTP connection to `cfg.mirrorRest`, or compromises the mirror node server itself.
2. They return a crafted JSON payload:
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [{"ip_address_v4": "169.254.169.254", "port": 80}]
     }]
   }
   ```
3. `fetchMirrorNodeNetwork()` produces `network["169.254.169.254:80"] = AccountID{0,0,3}`.
4. `hiero.ClientForNetwork(netmap)` (sdk_client.go line 22) configures the gRPC client to dial `169.254.169.254:80`.
5. All subsequent gRPC traffic (transaction submissions, queries) is directed to the attacker-controlled or internal address.

**Why existing checks fail:** The only validation is a nil/empty-string check on `host` and a zero-check on `port`. Neither prevents use of reserved or internal addresses.

### Impact Explanation
- **Network-level SSRF / internal probing:** The gRPC dialer will attempt TCP connections to arbitrary internal addresses, enabling port scanning of internal infrastructure from the pinger container.
- **Transaction redirection / total network shutdown:** All consensus node traffic is redirected to attacker-controlled endpoints. Transactions are never submitted to real consensus nodes, causing the pinger to report false failures or silently drop all transactions — matching the "Critical: Network not being able to confirm new transactions" severity classification.
- **Cloud metadata access (partial):** While gRPC to `169.254.169.254:50211` won't return AWS IMDS metadata directly, injecting `169.254.169.254:80` or using a `domain_name` that DNS-resolves to an internal address can reach HTTP-speaking internal services depending on how the SDK's underlying HTTP/2 transport behaves.

### Likelihood Explanation
- **Precondition:** `network=other` must be configured (operator choice for private/custom networks), and the attacker must control or intercept the mirror REST endpoint.
- **Feasibility:** The default example uses plain HTTP (`http://mirror-rest:5551`), making MITM trivial for any network-adjacent attacker (same pod network, compromised sidecar, ARP spoofing in a flat network). In Kubernetes environments without strict network policies, this is a realistic threat.
- **Repeatability:** The attack is persistent — `buildNetworkFromMirrorNodes` is called at startup and the poisoned network map is used for the lifetime of the client.

### Recommendation
1. **Validate returned IP addresses** before use. Reject any address in RFC-1918 (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`), loopback (`127/8`), and other reserved ranges using Go's `net.IP.IsLoopback()`, `IsLinkLocalUnicast()`, `IsPrivate()`.
2. **Enforce HTTPS** for the mirror REST endpoint, or at minimum document that plain HTTP is insecure and should not be used in production.
3. **Validate port range** — reject ports outside the expected gRPC range (e.g., only allow 50211–50212).
4. **Optionally pin expected node account IDs** against a known-good list so injected fake nodes are rejected.

Example guard to add before line 122 of `pinger/mirror_node_client.go`:
```go
if ip := net.ParseIP(host); ip != nil {
    if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
        continue // reject SSRF-exploitable addresses
    }
}
```

### Proof of Concept
**Preconditions:** Pinger configured with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`. Attacker can intercept HTTP traffic to `mirror-rest:5551` (e.g., via ARP spoofing or a compromised DNS entry).

**Steps:**
1. Stand up a mock HTTP server that responds to `GET /api/v1/network/nodes` with:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           {"ip_address_v4": "169.254.169.254", "domain_name": "", "port": 80},
           {"ip_address_v4": "10.0.0.1", "domain_name": "", "port": 50211}
         ]
       }
     ],
     "links": {"next": null}
   }
   ```
2. Point `HIERO_MIRROR_PINGER_REST` at the mock server.
3. Start the pinger. Observe that `hiero.ClientForNetwork` is called with `{"169.254.169.254:80": ..., "10.0.0.1:50211": ...}`.
4. All gRPC dials go to `169.254.169.254:80` and `10.0.0.1:50211` — internal addresses — instead of real consensus nodes.
5. No transactions are confirmed; the pinger reports total network failure. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** pinger/sdk_client.go (L17-22)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
