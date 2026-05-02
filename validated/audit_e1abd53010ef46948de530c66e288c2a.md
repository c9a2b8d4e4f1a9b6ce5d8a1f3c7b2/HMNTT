Audit Report

## Title
Unvalidated `domain_name` in Mirror Node Response Allows gRPC Endpoint Hijacking to Loopback

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` unconditionally trusts the `domain_name` field from the mirror node REST response and uses it as the gRPC host without any hostname or IP validation. An attacker who can intercept the plain-HTTP mirror node response can inject `"localhost"` (or any loopback-resolving hostname) as `domain_name`, causing the Hiero SDK client to route all gRPC calls to the loopback interface instead of real consensus nodes.

## Finding Description
The vulnerable loop is confirmed at `pinger/mirror_node_client.go` lines 113–124:

```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)   // line 114 — domain_name wins unconditionally
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4) // line 116 — only fallback
    }
    if host == "" || ep.Port == 0 {             // line 118 — only guard: non-empty + non-zero port
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId              // line 123 — injected into SDK network map
}
``` [1](#0-0) 

The resulting `network` map is passed directly to `hiero.ClientForNetwork(netmap)` at `pinger/sdk_client.go` line 22, configuring the SDK to dial those addresses for all gRPC calls. [2](#0-1) 

The HTTP client used to fetch the mirror node response is constructed at `pinger/mirror_node_client.go` line 46 with no custom transport and no TLS enforcement:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
``` [3](#0-2) 

The default example URL in `config.go` line 37 uses plain HTTP (`http://mirror-rest:5551`), confirming no TLS is expected or enforced on this path. [4](#0-3) 

**Note on one inaccuracy in the submitted report:** The report attributes the `&http.Client{...}` instantiation to `config.go` line 46. This is incorrect — it is at `mirror_node_client.go` line 46. `config.go` line 46 is unrelated flag-parsing code. This does not affect the validity of the finding; the HTTP client is still unauthenticated and the vulnerable code path is confirmed.

**Root cause:** No validation of the `domain_name` string — no allowlist, no loopback/RFC-1918 rejection, no format check. The only guards are a non-empty string and a non-zero port, both of which `"localhost:50211"` trivially satisfies.

**Failed assumption:** The code assumes the mirror node REST response is authoritative and trustworthy, but the transport is plain HTTP with no integrity protection.

## Impact Explanation
All gRPC calls (transfers, contract calls, any Hedera transaction) submitted by the pinger are silently routed to `127.0.0.1:50211` instead of real consensus nodes. Consequences:
- Pinger health/liveness signals become meaningless, masking real network outages.
- A local listener on that port could return crafted gRPC responses, producing false success signals.
- No direct fund theft, but monitoring integrity is fully compromised.

## Likelihood Explanation
- Applies only when `HIERO_MIRROR_PINGER_NETWORK=other` (custom deployment mode).
- The default mirror REST URL uses plain HTTP, making passive MITM trivial for any attacker with access to the pod's network namespace, the same Kubernetes node, or the cluster network fabric (compromised sidecar, rogue cluster node, cloud-provider network attacker).
- No cryptographic integrity protection exists on the mirror node response.
- The attack is repeatable on every pinger startup.

## Recommendation
1. **Reject loopback and RFC-1918 addresses** in `fetchMirrorNodeNetwork()`: after resolving `host`, check `net.IP.IsLoopback()` and `net.IP.IsPrivate()` and skip any endpoint that resolves to such addresses (or reject them by string match before resolution).
2. **Enforce HTTPS** on the mirror REST client when `network=other`, or at minimum support TLS with certificate verification via a configurable CA.
3. **Validate `domain_name` format** against an allowlist of expected suffixes (e.g., `.hedera.com`, `.hashgraph.com`) for known deployments.

## Proof of Concept
1. Attacker intercepts `GET /api/v1/network/nodes` response on the plain-HTTP path.
2. Attacker injects a node entry:
   ```json
   {
     "node_account_id": "0.0.3",
     "service_endpoints": [
       { "domain_name": "localhost", "ip_address_v4": "35.237.200.180", "port": 50211 }
     ]
   }
   ```
3. At `mirror_node_client.go:114`, `host = "localhost"` (non-empty, so line 116 is never reached).
4. At line 118, `"localhost" != ""` and `50211 != 0` — both guards pass.
5. `net.JoinHostPort("localhost", "50211")` → `"localhost:50211"` is inserted into the SDK network map.
6. `hiero.ClientForNetwork(netmap)` at `sdk_client.go:22` configures the SDK to dial `localhost:50211`.
7. All subsequent gRPC calls go to `127.0.0.1:50211`; no real consensus node is contacted.

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

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
