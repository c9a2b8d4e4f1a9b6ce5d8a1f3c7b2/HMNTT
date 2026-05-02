All four code references were verified against the actual source. Here is the result:

---

Audit Report

## Title
Crafted Mirror Node Response with Empty Service Endpoints Bypasses Retry Logic and Causes Fatal Pinger Crash

## Summary
In `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()` returns `retry = false` when a syntactically valid HTTP 200 response yields zero usable endpoints. This causes `buildNetworkFromMirrorNodes()` to skip all configured retries, propagates to `newClient()`, and terminates the pinger via `log.Fatalf`. An attacker who controls the mirror node HTTP response can trigger this condition on every pod restart, causing a persistent `CrashLoopBackOff`.

## Finding Description

**Verified code path:**

`fetchMirrorNodeNetwork()` silently skips any endpoint where both `domain_name` and `ip_address_v4` are empty: [1](#0-0) 

If no endpoints were added, the function returns `retry = false`: [2](#0-1) 

In `buildNetworkFromMirrorNodes()`, `retry = false` causes an immediate `break` on the very first attempt, skipping all configured retries and backoff: [3](#0-2) 

The error propagates through `newClient()` without recovery: [4](#0-3) 

And terminates the process in `main()`: [5](#0-4) 

**Root cause:** The code assigns `retry = false` to two fundamentally different conditions: (a) a genuine permanent misconfiguration, and (b) a semantically empty but syntactically valid response that is fully attacker-controllable. There is no distinction between the two.

**Failed assumption:** The developer assumed that a well-formed response with no usable endpoints indicates a permanent operator misconfiguration that should not be retried. An attacker controlling the mirror node can craft exactly this payload on every request, indefinitely.

**Exploit payload:**
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "domain_name": "", "ip_address_v4": "", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
```
This passes every guard: HTTP 200, valid JSON decode, non-empty `node_account_id`, parseable `AccountID` — but `host == ""` causes the endpoint to be skipped, leaving `network` empty, triggering the `retry = false` path.

## Impact Explanation
The pinger process calls `log.Fatalf` and exits immediately. In a Kubernetes deployment, the pod enters `CrashLoopBackOff`. The liveness heartbeat (`/tmp/alive`) stops being written, and the readiness file (`/tmp/ready`) is never created for new instances. The pinger — whose sole purpose is to continuously submit transactions to verify consensus node liveness — is completely silenced for as long as the attacker serves the crafted response. This is a full denial-of-service of the monitoring component for any `network=other` deployment. [6](#0-5) 

## Likelihood Explanation
The precondition is control over the mirror node HTTP response. No TLS certificate pinning is present — a plain `http.Client` with no custom TLS configuration is used: [7](#0-6) 

Attack vectors include: DNS hijacking of the mirror REST endpoint, BGP hijacking, TLS MITM (no pinning), or a compromised/malicious mirror node operator. The attack requires a single crafted HTTP response, is repeatable on every pod restart, and requires no authentication or privileged access to the pinger itself. The `network=other` mode is the explicit custom/private network path, making it the highest-value target for operators running their own Hiero networks.

## Recommendation

1. **Change `retry = false` to `retry = true`** for the "no usable endpoints" case at line 128. An empty endpoint list from an otherwise valid response is ambiguous — it may be transient or attacker-induced — and should be retried with backoff like any other transient failure.

2. **Add a minimum-node threshold check** before accepting a network map (e.g., require at least one usable endpoint after all pages are fetched).

3. **Replace `log.Fatalf` in `main()`** with a retry loop at the application level, so a startup failure does not permanently kill the process without exhausting all retry attempts.

4. **Consider TLS certificate pinning or at minimum HTTPS enforcement** for the mirror node client to reduce the MITM attack surface.

## Proof of Concept

Serve the following JSON at the configured mirror REST endpoint with HTTP 200:

```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "domain_name": "", "ip_address_v4": "", "port": 50211 }
      ]
    }
  ],
  "links": { "next": null }
}
```

On startup, `fetchMirrorNodeNetwork()` will parse the response successfully, skip the endpoint due to empty host, return `(nil, false, error)`, `buildNetworkFromMirrorNodes()` will break immediately without retrying, `newClient()` will return the error, and `main()` will call `log.Fatalf`, exiting the process. Every subsequent pod restart will repeat this sequence as long as the crafted response is served.

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

**File:** pinger/main.go (L28-49)
```go
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = os.WriteFile("/tmp/alive", []byte(time.Now().Format(time.RFC3339Nano)), 0644)
			}
		}
	}()

	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}

	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```
