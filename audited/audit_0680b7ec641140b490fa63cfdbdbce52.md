### Title
Unauthenticated Mirror REST Response Allows Partial Node-Set Injection, Causing Selective Health-Check Blindness for ≥70% of Consensus Nodes

### Summary
`buildNetworkFromMirrorNodes()` in `pinger/mirror_node_client.go` unconditionally trusts the JSON payload returned by the configured mirror REST endpoint and builds the entire SDK network map from it. Because the endpoint URL may be plain HTTP and the response carries no signature or minimum-node-count constraint, any attacker who can intercept or serve that HTTP response can inject a `nodesEnvelope` listing only a chosen subset of nodes. The pinger then routes all transactions exclusively to those nodes for its entire lifetime, making every omitted node appear to fail health checks.

### Finding Description

**Code path:**

`pinger/sdk_client.go` `newClient()` (line 18) calls `buildNetworkFromMirrorNodes()` exactly once at startup. [1](#0-0) 

`buildNetworkFromMirrorNodes()` issues a plain `GET` over whatever scheme is in `cfg.mirrorRest` (the example in the flag help is `http://mirror-rest:5551`, i.e. cleartext HTTP). [2](#0-1) 

`fetchMirrorNodeNetwork()` decodes the JSON body and iterates over `payload.Nodes`, adding every `serviceEndpoint` with a non-empty host and non-zero port to the network map. [3](#0-2) 

**The only guard** against a malicious response is:

```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
``` [4](#0-3) 

A response containing even a single node passes this check. There is:
- No minimum node count (e.g., ≥ N nodes required).
- No cross-check against a known/expected node-account-ID set.
- No TLS enforcement or certificate pinning.
- No HMAC/signature on the response body.
- No re-fetch after startup; the poisoned map persists for the pinger's lifetime.

**Exploit flow:**

1. Attacker positions themselves to intercept the HTTP GET to `cfg.mirrorRest` (DNS poisoning, ARP spoofing on the same LAN, BGP hijack, or simply operating a malicious mirror node that the operator was tricked into configuring).
2. Attacker returns a well-formed `nodesEnvelope` containing only 3 of the 10 real consensus nodes, with valid `node_account_id` values and `service_endpoints` pointing to those 3 nodes' real gRPC addresses (or attacker-controlled proxies).
3. `fetchMirrorNodeNetwork()` accepts the response: `len(network) == 3 > 0`.
4. `hiero.ClientForNetwork(netmap)` is called with only those 3 entries.
5. Every subsequent `cryptoTransfer.Execute(client)` in `submitWithRetry()` is dispatched only to those 3 nodes.
6. The remaining 7 nodes receive zero pinger transactions; the health-check system records them as non-responsive.

### Impact Explanation

The pinger is the active health-monitoring component for consensus nodes. Concentrating 100% of its traffic on 3 of 10 nodes causes the monitoring plane to report 7 nodes (70%) as unhealthy or unreachable. Operators or automated systems acting on those health signals may quarantine, restart, or remove those nodes from service, constituting a ≥30% effective shutdown of network processing capacity without any brute-force action against the nodes themselves. The impact is persistent for the entire pinger process lifetime because the network map is never refreshed.

### Likelihood Explanation

For deployments using `network=other` with a plain `http://` mirror REST URL (the documented default example), a network-adjacent attacker (same subnet, compromised DNS resolver, or rogue mirror node) can execute this with no Hiero-level credentials. The mirror node is a less-hardened component than consensus nodes and is a realistic compromise target. The attack is repeatable: every pinger restart re-fetches the poisoned endpoint.

### Recommendation

1. **Enforce HTTPS** for `mirrorRest` and reject `http://` URLs at config validation time.
2. **Enforce a minimum node count**: reject any response where `len(network) < minExpectedNodes` (configurable, e.g., default 5).
3. **Validate returned node-account-IDs** against a locally configured allowlist of expected node IDs.
4. **Periodically re-fetch** the node list (e.g., every N minutes) so a poisoned startup response does not persist indefinitely; apply the same validation on refresh.
5. Consider **response signing** at the mirror node layer so the pinger can verify authenticity before trusting the payload.

### Proof of Concept

```
# 1. Stand up a fake mirror REST server returning only 3 nodes:
cat > fake_nodes.json <<'EOF'
{
  "nodes": [
    {"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"10.0.0.3","port":50211}]},
    {"node_account_id":"0.0.4","service_endpoints":[{"ip_address_v4":"10.0.0.4","port":50211}]},
    {"node_account_id":"0.0.5","service_endpoints":[{"ip_address_v4":"10.0.0.5","port":50211}]}
  ],
  "links":{"next":null}
}
EOF
python3 -m http.server 8080 &   # serves fake_nodes.json at /api/v1/network/nodes

# 2. Start pinger pointing at the fake mirror:
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://127.0.0.1:8080 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# 3. Observe: pinger builds a 3-entry network map; nodes 0.0.6–0.0.12
#    receive zero transactions; health dashboard marks them unhealthy.
```

The `len(network) == 0` guard is bypassed because 3 > 0, and no other check rejects the truncated response. [4](#0-3)

### Citations

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

**File:** pinger/mirror_node_client.go (L100-125)
```go
	network := make(map[string]hiero.AccountID)

	for _, n := range payload.Nodes {
		if n.NodeAccountID == "" {
			continue
		}

		nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
		if err != nil {
			continue
		}

		// Use service_endpoints for node gRPC (what the SDK wants)
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
```

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```
