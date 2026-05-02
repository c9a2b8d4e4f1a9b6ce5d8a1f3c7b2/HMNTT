### Title
Mirror-Node Response Poisoning via All-Zero Ports Causes Non-Retryable Fatal Termination of Pinger

### Summary
When `cfg.network == "other"`, the pinger bootstraps its Hiero SDK client exclusively from the mirror node REST API. If an attacker can deliver a response where every `serviceEndpoint.port` is `0`, the `ep.Port == 0` guard silently discards every endpoint, the empty-network sentinel returns `retry=false`, all configured retries are bypassed in a single round-trip, and `main.go` calls `log.Fatalf`, permanently killing the process and halting all fund transfers until a human restarts it.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go` lines 113–120 — inner loop over `ServiceEndpoints`:
```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {   // ← silently skips Port-0 endpoints
        continue
    }
    ...
}
``` [1](#0-0) 

`pinger/mirror_node_client.go` lines 127–129 — empty-network sentinel:
```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
```
The second return value (`false`) means **do not retry**. [2](#0-1) 

`pinger/mirror_node_client.go` lines 58–61 — retry loop breaks immediately on `retry=false`:
```go
lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
if !retry || attempt == attempts {
    break
}
```
Even with `mirrorNodeClientMaxRetries=10`, a single poisoned response exhausts all retries. [3](#0-2) 

`pinger/sdk_client.go` lines 18–21 — error propagates out of `newClient`:
```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
if err != nil {
    return nil, err
}
``` [4](#0-3) 

`pinger/main.go` lines 41–44 — `log.Fatalf` terminates the process:
```go
client, err := newClient(cfg)
if err != nil {
    log.Fatalf("client error: %v", err)
}
``` [5](#0-4) 

**Root cause / failed assumption:** The code assumes the mirror node REST endpoint is always trusted and always returns at least one valid port. There is no integrity check, no TLS certificate pinning, and no fallback. The `retry=false` sentinel was designed for "bad data" (not a transient error), so it intentionally skips retries — but this makes a single poisoned response sufficient to kill the process.

### Impact Explanation

The pinger's sole purpose is to submit periodic HBAR transfers to prove liveness of the network. A successful attack:
- Terminates the pinger process via `log.Fatalf` before it ever writes `/tmp/ready`.
- Prevents all subsequent fund transfers for the lifetime of the stopped process.
- Causes the Kubernetes readiness probe (`/tmp/ready`) to never be created, taking the pod out of service.
- The liveness heartbeat (`/tmp/alive`) also stops, eventually triggering a pod restart — but if the mirror node response is persistently poisoned, every restart immediately re-triggers the same fatal path.

Severity: **High** — complete, repeatable denial of the pinger's core function.

### Likelihood Explanation

The precondition is that the attacker can influence the mirror node REST response. This is achievable by:

1. **HTTP deployment (most likely):** The config comment and default example explicitly show `http://mirror-rest:5551` as the expected URL. [6](#0-5) 
The HTTP client has no TLS enforcement:
```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
``` [7](#0-6) 
Any network-adjacent attacker (same cluster, same subnet, compromised sidecar) can MITM a plaintext HTTP connection with zero privileges.

2. **DNS poisoning:** If the mirror REST URL uses a hostname, DNS poisoning redirects requests to an attacker-controlled server.

3. **Compromised mirror node:** A mirror node serving malicious data is within the threat model for a "custom network" (`network=other`), which is exactly the code path that calls `buildNetworkFromMirrorNodes`.

The attack is trivially repeatable: serve `{"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"ip_address_v4":"1.2.3.4","port":0}]}],"links":{}}` once, and the process dies permanently.

### Recommendation

1. **Make empty-network non-fatal and retryable:** Change the sentinel at line 127 to return `retry=true` so the retry loop actually retries on a poisoned/empty response:
   ```go
   if len(network) == 0 {
       return nil, true, fmt.Errorf("no usable service_endpoints found from %s", url)
   }
   ```

2. **Do not `log.Fatalf` on bootstrap failure:** Replace `log.Fatalf` in `main.go` with a retry loop that keeps attempting `newClient` until the context is cancelled, so a transient or poisoned response does not permanently kill the process.

3. **Enforce HTTPS with certificate validation:** Reject `http://` mirror REST URLs or enforce TLS with a pinned CA, preventing MITM on plaintext connections.

4. **Validate minimum endpoint count:** Require at least N valid endpoints before accepting the response as legitimate.

### Proof of Concept

**Preconditions:** Attacker can intercept or respond to HTTP requests to the configured `HIERO_MIRROR_PINGER_REST` URL (e.g., via ARP spoofing, DNS poisoning, or a rogue service on the same cluster network).

**Steps:**

1. Deploy pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
2. Intercept the GET request to `http://mirror-rest:5551/api/v1/network/nodes`.
3. Return HTTP 200 with body:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           {"ip_address_v4": "1.2.3.4", "domain_name": "", "port": 0}
         ]
       }
     ],
     "links": {"next": null}
   }
   ```
4. `fetchMirrorNodeNetwork` skips the endpoint (`ep.Port == 0`), `len(network) == 0`, returns `retry=false`.
5. `buildNetworkFromMirrorNodes` breaks out of the retry loop immediately (regardless of `mirrorNodeClientMaxRetries`).
6. `newClient` returns an error.
7. `main.go` calls `log.Fatalf("client error: ...")` — process exits with status 1.
8. `/tmp/ready` is never written; readiness probe fails; pod is removed from load balancing.
9. If the pod auto-restarts, repeat step 3 on every startup to maintain permanent denial.

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L58-61)
```go
		lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		if !retry || attempt == attempts {
			break
		}
```

**File:** pinger/mirror_node_client.go (L113-120)
```go
		for _, ep := range n.ServiceEndpoints {
			host := strings.TrimSpace(ep.DomainName)
			if host == "" {
				host = strings.TrimSpace(ep.IPAddressV4)
			}
			if host == "" || ep.Port == 0 {
				continue
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

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
