### Title
Unauthenticated Mirror Node Response Enables DoS via All-Zero-Port Endpoint Injection

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` makes an unauthenticated HTTP GET to the configured mirror REST URL and blindly trusts the JSON response. An attacker who can intercept or spoof that response (via network MITM or DNS poisoning, which is realistic when the URL is plain HTTP) can return a payload where every `serviceEndpoint` has `Port: 0`. All endpoints are silently dropped by the `ep.Port == 0` guard, the resulting network map is empty, and the function returns `retry=false` — permanently bypassing the retry mechanism and causing the pinger to abort at startup.

### Finding Description

**Code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–131.

The HTTP client is constructed with only a timeout — no TLS enforcement, no certificate pinning, no response authentication:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
``` [1](#0-0) 

The default/example mirror REST URL is `http://mirror-rest:5551` (plain HTTP): [2](#0-1) 

The response is decoded and iterated with no integrity check. The port-zero guard silently skips every endpoint:

```go
if host == "" || ep.Port == 0 {
    continue
}
``` [3](#0-2) 

When the resulting map is empty, the function returns `retry=false`:

```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
``` [4](#0-3) 

In `buildNetworkFromMirrorNodes`, `retry=false` causes an immediate break regardless of how many retries are configured:

```go
if !retry || attempt == attempts {
    break
}
``` [5](#0-4) 

`newClient()` propagates the error, and `main()` calls `log.Fatalf`, killing the process: [6](#0-5) [7](#0-6) 

**Root cause:** The function unconditionally trusts the HTTP response body. There is no TLS requirement, no HMAC/signature verification, and no sanity check that at least one endpoint has a non-zero port before accepting the response as authoritative.

**Failed assumption:** The code assumes the mirror REST API response is always authentic and well-formed. The `retry=false` path was designed for "server gave a valid but empty answer," but a spoofed response is indistinguishable from a legitimate one.

### Impact Explanation

Complete denial-of-service of the pinger at startup. The pinger never reaches the ticker loop, never submits any transactions, and the liveness/readiness probes (`/tmp/alive`, `/tmp/ready`) are never written. In a Kubernetes deployment this causes the pod to be restarted in a crash loop, and transaction monitoring is suppressed for as long as the attacker can sustain the spoofed response. This affects only `network=other` deployments; `testnet`/`mainnet`/`previewnet` use hardcoded SDK endpoints. [8](#0-7) 

### Likelihood Explanation

**Precondition:** The attacker must be able to intercept or replace the HTTP response from the mirror REST endpoint. This is realistic when:

1. The mirror REST URL uses plain HTTP (the documented default example is `http://`), making the connection susceptible to ARP spoofing or network-level MITM on the same L2 segment.
2. The hostname (e.g., `mirror-rest`) is resolved via a DNS server the attacker can poison (e.g., a compromised CoreDNS in the same Kubernetes namespace, or a misconfigured external DNS).
3. The mirror node REST API is publicly reachable over HTTP — common for custom/private deployments using `network=other`.

No application-layer credentials or privileges are required. The attack is repeatable: each pinger restart re-queries the mirror node, so the attacker only needs to sustain the spoofed DNS/network state.

### Recommendation

1. **Enforce HTTPS** for the mirror REST URL; reject `http://` schemes at config validation time.
2. **Treat empty-network as retryable**: change `return nil, false, ...` to `return nil, true, ...` at line 128 so that a suspiciously empty response triggers the retry/backoff loop rather than an immediate fatal exit.
3. **Add a minimum-endpoint sanity check**: if the parsed response contains nodes but zero usable endpoints, log a warning and retry rather than treating it as a permanent error.
4. **Optional:** verify the mirror node TLS certificate against a pinned CA or a configurable trust store.

### Proof of Concept

1. Configure the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
2. Position an attacker-controlled HTTP server to respond to requests for `http://mirror-rest:5551/api/v1/network/nodes` (via DNS poisoning of `mirror-rest` or ARP/network MITM).
3. Return the following JSON body with HTTP 200:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           {"domain_name": "node.example.com", "ip_address_v4": "", "port": 0},
           {"domain_name": "", "ip_address_v4": "1.2.3.4", "port": 0}
         ]
       }
     ],
     "links": {"next": null}
   }
   ```
4. Start the pinger. `fetchMirrorNodeNetwork` filters all endpoints (port == 0), returns `(nil, false, error)`. `buildNetworkFromMirrorNodes` breaks immediately (retry=false). `newClient` returns error. `main` calls `log.Fatalf`. The pinger exits without ever submitting a transaction.
5. Repeat for every pod restart to maintain the DoS.

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

**File:** pinger/mirror_node_client.go (L118-120)
```go
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L16-29)
```go
	switch cfg.network {
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
```

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```
