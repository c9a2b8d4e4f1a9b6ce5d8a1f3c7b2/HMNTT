### Title
Silent Partial Network Erasure via Crafted Mirror REST Response in `fetchMirrorNodeNetwork()`

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` silently discards any `nodeEntry` whose every `serviceEndpoint` has both `domain_name` and `ip_address_v4` as empty strings. The only guard against a poisoned response is a check that the resulting map is non-empty, so an attacker who can serve a crafted mirror REST response can cause 1–99% of consensus nodes to be silently dropped from the pinger's network view while the function returns success. An attacker with network-level access (e.g., on the same segment as the pinger, or able to perform DNS hijacking) can exploit this because the pinger makes unauthenticated, unverified HTTP requests with no response-integrity check.

### Finding Description
**Exact code path:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 113–129.

```
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)   // line 114
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4) // line 116
    }
    if host == "" || ep.Port == 0 {             // line 118
        continue                                 // silently skip
    }
    ...
}
// Only guard:
if len(network) == 0 {                          // line 127
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
return network, false, nil                      // success even if 99% of nodes dropped
```

**Root cause / failed assumption:** The code assumes that any non-empty result set is a valid network view. It never validates that the returned node count is within an acceptable fraction of the total nodes advertised in the response. A node entry with all-empty-host endpoints contributes zero entries to `network` and is silently ignored.

**Exploit flow:**
1. The attacker positions themselves to intercept or replace the HTTP response from the mirror REST URL (see preconditions below).
2. They craft a JSON payload where ≥30% of `nodes` entries have `service_endpoints` arrays whose every element has `"domain_name": ""` and `"ip_address_v4": ""` (with any port value, including non-zero).
3. The remaining ≤70% of nodes have valid endpoints, so `len(network) > 0` and the function returns success.
4. The pinger builds its Hiero SDK client (`hiero.ClientForNetwork(netmap)` in `sdk_client.go` line 22) using only the surviving nodes.
5. The pinger never detects or logs the missing nodes; it operates silently on a reduced network view.

**Why existing checks fail:** The sole guard at line 127 (`len(network) == 0`) only catches total erasure. Partial erasure of any magnitude from 1% to 99% passes through undetected and unreported.

**Preconditions for an external attacker:**
- The default example mirror REST URL in `config.go` line 37 is `http://mirror-rest:5551` — plain HTTP. An attacker on the same network segment can trivially MITM this traffic.
- Even with HTTPS, there is no certificate pinning and no response-body signature verification, so DNS hijacking (redirecting the mirror hostname to an attacker-controlled server with a valid certificate from any trusted CA) is sufficient.
- No authentication token or HMAC is required on the mirror REST response; the pinger accepts any well-formed JSON with HTTP 2xx.

### Impact Explanation
The pinger's Hiero SDK client is initialized once at startup with the poisoned network map. For the lifetime of the process, it will only submit transactions to the surviving ≤70% of nodes. The 30%+ silently-dropped nodes receive no pings, so any failure or degradation on those nodes goes undetected by the monitoring system. In the context of the severity classification, this constitutes effective "shutdown" of ≥30% of the nodes from the pinger's perspective — the monitoring blind spot is permanent until the pinger is restarted with a clean response.

### Likelihood Explanation
- **Network=other deployments** (the only path that calls `fetchMirrorNodeNetwork`) are explicitly configured with a custom mirror REST URL, which in practice is often an internal cluster URL over plain HTTP (as shown by the default example).
- An attacker on the same Kubernetes cluster, pod network, or physical segment can ARP-spoof or DNS-poison the mirror REST service name with no credentials.
- The crafted payload is trivial to construct: valid JSON, valid `node_account_id` values, and empty-string endpoint fields.
- The attack is repeatable and leaves no error in logs (the function returns nil error).

### Recommendation
1. **Enforce a minimum usable-node threshold:** After building `network`, compare `len(network)` against `len(payload.Nodes)` (or a configured minimum). If the fraction of usable nodes falls below a threshold (e.g., 80%), return an error and trigger a retry.
2. **Log and count skipped nodes:** Emit a warning for every node whose endpoints are all unusable, so operators can detect partial poisoning.
3. **Enforce HTTPS and validate the server certificate:** Reject `mirrorRest` URLs with an `http://` scheme, or at minimum document and enforce TLS in deployment manifests.
4. **Consider response signing:** Have the mirror node sign its `/network/nodes` response body (e.g., with an operator key), and have the pinger verify the signature before trusting the payload.

### Proof of Concept
Stand up a local HTTP server that returns the following JSON at `GET /api/v1/network/nodes`:

```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        {"domain_name": "", "ip_address_v4": "", "port": 50211}
      ]
    },
    {
      "node_account_id": "0.0.4",
      "service_endpoints": [
        {"domain_name": "", "ip_address_v4": "", "port": 50211}
      ]
    },
    {
      "node_account_id": "0.0.5",
      "service_endpoints": [
        {"domain_name": "node5.example.com", "ip_address_v4": "", "port": 50211}
      ]
    }
  ],
  "links": {"next": null}
}
```

Configure the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-server>`.

**Expected result:** `fetchMirrorNodeNetwork` returns `{"node5.example.com:50211": AccountID{0,0,5}}` with no error. Nodes `0.0.3` and `0.0.4` (66% of the network) are silently absent. The pinger starts, writes `/tmp/ready`, and operates indefinitely without ever pinging nodes 3 or 4. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** pinger/mirror_node_client.go (L113-129)
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
	}

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```
