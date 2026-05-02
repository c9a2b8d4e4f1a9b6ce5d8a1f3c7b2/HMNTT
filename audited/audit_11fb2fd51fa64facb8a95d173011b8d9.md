### Title
DNS-Spoofed Empty-Endpoint Response Bypasses All Retries and Crashes the Pinger at Startup

### Summary
`fetchMirrorNodeNetwork()` returns `retry=false` when the parsed node list yields zero usable endpoints (`len(network) == 0`). Because the retry loop in `buildNetworkFromMirrorNodes()` breaks immediately on `retry=false`, a single DNS-spoofed HTTP 200 response carrying nodes with empty `service_endpoints` exhausts all retry budget in one shot, causing `newClient()` to return an error and `main()` to call `log.Fatalf`, terminating the process. If the attacker sustains DNS control, every restart attempt fails identically, producing indefinite denial of service.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go` lines 127-129 — the only path that sets `retry=false` for a semantically valid (HTTP 200, well-formed JSON) response:
```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
``` [1](#0-0) 

`pinger/mirror_node_client.go` lines 59-61 — the retry loop breaks immediately when `retry=false`:
```go
if !retry || attempt == attempts {
    break
}
``` [2](#0-1) 

`pinger/sdk_client.go` lines 18-21 — `buildNetworkFromMirrorNodes` is called only for `network=other`; its error is propagated directly:
```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
if err != nil {
    return nil, err
}
``` [3](#0-2) 

`pinger/main.go` lines 41-43 — `newClient` failure is fatal:
```go
client, err := newClient(cfg)
if err != nil {
    log.Fatalf("client error: %v", err)
}
``` [4](#0-3) 

**Root cause and failed assumption:**

The code assumes that a well-formed HTTP 200 JSON response with zero usable endpoints is a permanent, non-transient condition (hence `retry=false`). This assumption fails when the response is attacker-controlled: the attacker can always serve a structurally valid payload that passes JSON decoding and the `node_account_id` check but contributes zero entries to `network` — for example, nodes whose every `service_endpoint` has `domain_name=""`, `ip_address_v4=""`, or `port=0`. [5](#0-4) 

The asymmetry is stark: network-level errors get `retry=true` (line 86), HTTP 429/5xx get `retry=true` (line 91), but a semantically empty-but-valid 200 response gets `retry=false`, meaning the configured `mirrorNodeClientMaxRetries=10` is completely bypassed by a single injected response. [6](#0-5) 

**No TLS enforcement:** The `http.Client` is constructed with no custom TLS configuration and the documented default URL is `http://mirror-rest:5551` (plain HTTP), so no certificate is required to serve the spoofed response. [7](#0-6) [8](#0-7) 

### Impact Explanation

The pinger process terminates via `log.Fatalf` on the very first startup attempt. As long as the attacker maintains DNS control, every container restart (including Kubernetes liveness/readiness restarts) hits the same spoofed response and crashes again. The `/tmp/ready` readiness file is never written, so the pod never becomes ready. All Hiero transaction submissions from this pinger instance are blocked for the duration of the attack. This is a complete, repeatable denial of service against the `network=other` deployment mode. [9](#0-8) 

### Likelihood Explanation

The attack requires `network=other` to be configured (the custom/self-hosted deployment path) and the ability to answer DNS queries for the mirror REST hostname before the legitimate server does. Feasible vectors include: DNS cache poisoning of the cluster's resolver (e.g., CoreDNS), a compromised internal DNS server, or a misconfigured split-horizon DNS. For plain-HTTP deployments (the documented default), no TLS certificate is needed, reducing attacker requirements to DNS response injection only. The attack is repeatable on every process restart and requires no authentication or privileged OS access. [10](#0-9) 

### Recommendation

1. **Change `retry` to `true` for the empty-network case** so that all configured retries are consumed before giving up:
   ```go
   // line 128 — was: return nil, false, fmt.Errorf(...)
   return nil, true, fmt.Errorf("no usable service_endpoints found from %s", url)
   ``` [1](#0-0) 

2. **Enforce HTTPS** for the mirror REST URL and validate the server certificate. Reject plain `http://` URLs at config load time. [11](#0-10) 

3. **Add a minimum-node threshold** (e.g., require at least N nodes with valid endpoints) and treat falling below it as a retryable error.

4. **Re-fetch the network map periodically** (not only at startup) so a transient DNS attack does not permanently disable the pinger.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`
- Attacker can inject DNS responses for `mirror-rest` (e.g., via CoreDNS ConfigMap edit, DNS cache poisoning, or a rogue DNS server on the same network)

**Steps:**

1. Stand up a minimal HTTP server on attacker-controlled IP that responds to `GET /api/v1/network/nodes` with:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": []
       }
     ],
     "links": { "next": null }
   }
   ```
   HTTP status 200, `Content-Type: application/json`.

2. Poison DNS so that `mirror-rest` resolves to the attacker's IP.

3. Start (or restart) the pinger container.

4. **Observed result:**
   - `fetchMirrorNodeNetwork` receives HTTP 200, decodes the payload, iterates over zero endpoints, reaches `len(network) == 0`, returns `nil, false, error`.
   - `buildNetworkFromMirrorNodes` hits `!retry` on the first attempt and breaks without any retry.
   - `newClient` returns the error.
   - `main` calls `log.Fatalf("client error: no usable service_endpoints found from http://mirror-rest:5551/api/v1/network/nodes")` and the process exits with status 1.
   - `/tmp/ready` is never created; the pod never becomes ready; all transaction submissions are blocked.

5. Repeat DNS injection on every restart to sustain the DoS indefinitely.

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L59-61)
```go
		if !retry || attempt == attempts {
			break
		}
```

**File:** pinger/mirror_node_client.go (L86-92)
```go
		return nil, true, fmt.Errorf("GET %s failed: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
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

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/sdk_client.go (L18-21)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/main.go (L41-43)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
```

**File:** pinger/main.go (L47-49)
```go
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```

**File:** pinger/config.go (L36-37)
```go
	flag.StringVar(&cfg.network, "network", envOr("HIERO_MIRROR_PINGER_NETWORK", "testnet"), "network: testnet|previewnet|mainnet|other")
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/config.go (L133-135)
```go
	if cfg.network == "other" && strings.TrimSpace(cfg.mirrorRest) == "" {
		return cfg, fmt.Errorf("HIERO_MIRROR_PINGER_NETWORK=other requires HIERO_MIRROR_PINGER_REST")
	}
```
