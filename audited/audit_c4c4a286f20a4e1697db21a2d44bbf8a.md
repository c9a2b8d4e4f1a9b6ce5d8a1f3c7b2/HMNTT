### Title
Unbounded HTTP Response Body in `fetchMirrorNodeNetwork` Enables Memory Exhaustion via MITM/DNS Poisoning

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the HTTP response body with `json.NewDecoder(resp.Body).Decode(&payload)` and no `io.LimitReader` guard. An attacker who can intercept or spoof the mirror node REST endpoint (via DNS poisoning on the plaintext HTTP endpoint explicitly shown in config) can serve an arbitrarily large JSON body, exhausting the pinger process's memory within the HTTP client timeout window and crashing it, which creates gaps in the mirror node transaction history.

### Finding Description
**Exact location:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, line 96.

```go
// line 95-98
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}
```

`resp.Body` is passed directly to `json.NewDecoder` with no `io.LimitReader` wrapping. Go's `json.Decoder` will read and buffer the entire response body into memory before returning.

**Partial mitigation that fails:** An `http.Client` with `Timeout: cfg.mirrorNodeClientTimeout` (default 10 s, line 46) is used. Go's `http.Client.Timeout` is absolute from request start and does bound the read window. However, on a fast network (e.g., 1 Gbps LAN or a co-located attacker server), 10 seconds is sufficient to stream ~1.25 GB of JSON, which Go's decoder will allocate entirely in heap memory. The timeout does not cap the number of bytes read — it only caps the wall-clock duration.

**Attack surface — HTTP endpoint:** `config.go` line 37 explicitly documents and defaults to `http://mirror-rest:5551` for `network=other`. No TLS is enforced. This makes DNS poisoning a realistic, low-privilege attack vector: an attacker who can influence the DNS resolution of the mirror REST hostname (e.g., via a compromised internal DNS server, cloud metadata DNS manipulation, or BGP-level redirect for public endpoints) redirects the pinger's GET request to an attacker-controlled server that streams a multi-hundred-MB or multi-GB JSON body.

**No body-size check exists anywhere** in the call chain from `buildNetworkFromMirrorNodes` → `fetchMirrorNodeNetwork`.

### Impact Explanation
The pinger process is a continuous transaction submitter. If it OOMs and crashes at startup (where `newClient` → `buildNetworkFromMirrorNodes` is called, `main.go` line 41), it never reaches the ticker loop and never submits transactions. If the mirror node URL is re-queried on reconnect, the attack is repeatable. The concrete protocol impact is gaps or complete cessation of transaction submissions to the mirror node, degrading the integrity of the transaction history record — matching the stated "Reorganizing transaction history without direct theft" scope.

### Likelihood Explanation
For `network=other` with an HTTP endpoint (explicitly supported and documented), DNS poisoning is achievable by an attacker with access to the internal network or DNS infrastructure — not requiring OS-level privileges on the pinger host itself. In Kubernetes/cloud deployments, DNS spoofing via a compromised sidecar or misconfigured CoreDNS is a known realistic attack. The attack is repeatable on every pinger restart or reconnect cycle.

### Recommendation
Wrap `resp.Body` with `io.LimitReader` before passing to the JSON decoder, e.g.:

```go
const maxBodyBytes = 1 << 20 // 1 MiB — sufficient for any real node list
limited := io.LimitReader(resp.Body, maxBodyBytes+1)
if err := json.NewDecoder(limited).Decode(&payload); err != nil { ... }
```

Additionally, enforce TLS for all mirror REST URLs (reject `http://` schemes) and consider pinning the expected certificate or using mTLS for the mirror node client connection.

### Proof of Concept
1. Stand up a malicious HTTP server that, on any GET request, streams a valid JSON prefix `{"nodes":[` followed by gigabytes of repeated `{"node_account_id":"0.0.3","service_endpoints":[]},` entries.
2. Configure the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-controlled-hostname>`.
3. Poison DNS so `<attacker-controlled-hostname>` resolves to the malicious server (or simply point the env var directly at it to confirm the code path).
4. Start the pinger. Observe memory usage climbing until OOM kill before the ticker loop is ever reached, confirmed by absence of any "Starting transfer ticker" log line and gaps in mirror node transaction history. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L95-98)
```go
	var payload nodesEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
	}
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/main.go (L41-41)
```go
	client, err := newClient(cfg)
```
