All code references have been verified against the actual source. Here is the result:

---

Audit Report

## Title
Unauthenticated Mirror Node Response Injects Tarpit gRPC Endpoints, Freezing All Transaction Submissions

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` accepts any `service_endpoints` host/port from a plain-HTTP mirror node response without IP/hostname validation. The SDK client built from those endpoints has no gRPC connection timeout, and `Execute(client)` in `pinger/transfer.go` is called without a context deadline. A network-level MITM on the HTTP channel can inject tarpit endpoints, permanently stalling all transaction submissions while the liveness probe continues to pass.

## Finding Description

**Root cause 1 — No endpoint validation in `fetchMirrorNodeNetwork`:**

The only guards applied to each `ServiceEndpoint` are that `host` is non-empty and `port != 0`. No IP allowlist, no RFC-1918 block, no hostname validation is performed. [1](#0-0) 

**Root cause 2 — Plain HTTP with only a read timeout:**

The HTTP client is constructed with only a read timeout; no TLS is enforced on the upstream fetch. [2](#0-1) 

The default `mirrorRest` URL is documented as `http://mirror-rest:5551` — plain HTTP. [3](#0-2) 

**Root cause 3 — Status-code check passes any crafted 200:** [4](#0-3) 

**Root cause 4 — SDK client built with no gRPC timeout:**

`hiero.ClientForNetwork(netmap)` is called with no `SetRequestTimeout` or connection deadline configured. [5](#0-4) 

**Root cause 5 — `Execute` called without a context deadline:**

`ctx.Err()` is checked only *between* retry attempts (line 24), not *during* a blocking `Execute` call (line 33). A hanging gRPC dial is never interrupted. [6](#0-5) 

**Exploit flow:**
1. Attacker performs a network-level MITM on the plain-HTTP channel between the pinger and `http://mirror-rest:5551`.
2. Intercepts `GET /api/v1/network/nodes` and returns a crafted 200 response with `service_endpoints` pointing to a tarpit IP on port 50211.
3. `fetchMirrorNodeNetwork` accepts it: valid `NodeAccountID`, non-empty host, non-zero port — all guards pass, `len(network) == 1 > 0`.
4. `hiero.ClientForNetwork(netmap)` builds the SDK client pointing exclusively at the tarpit.
5. Every `cryptoTransfer.Execute(client)` blocks indefinitely on gRPC dial; the retry loop never advances.

## Impact Explanation

All transaction submissions are permanently frozen for the lifetime of the process. The liveness heartbeat goroutine writes `/tmp/alive` every 15 seconds independently of the transfer loop, so the Kubernetes exec probe never detects the hang — the pod appears healthy while being completely non-functional. [7](#0-6) 

## Likelihood Explanation

The precondition is a network-level MITM on a plain-HTTP connection. This is realistic in:
- Container/Kubernetes environments where the mirror REST service is on an internal HTTP endpoint (the documented default `http://mirror-rest:5551`).
- Shared-network deployments susceptible to ARP spoofing or rogue DHCP.
- Environments where DNS for the mirror REST hostname is attacker-influenced.

No credentials, no privileged keys, and no access to the pinger host are required — only the ability to intercept one unauthenticated HTTP response at startup.

## Recommendation

1. **Enforce TLS** on the mirror REST connection, or at minimum validate the server certificate when TLS is used.
2. **Validate returned endpoints** against an allowlist of expected IP ranges or hostnames before building the network map.
3. **Set a gRPC request timeout** on the SDK client (e.g., `client.SetRequestTimeout(30 * time.Second)`).
4. **Propagate the context deadline** into `Execute` — use `ExecuteWithContext(ctx, client)` if the SDK supports it, or wrap the call in a goroutine with a `context.WithTimeout`.
5. **Tie the liveness probe** to actual transaction success, not just process aliveness, so a frozen transfer loop is detectable.

## Proof of Concept

```
# 1. Stand up a tarpit listener (never responds)
nc -lk 50211 &

# 2. MITM the HTTP channel (e.g., via iptables redirect or rogue DNS)
#    Serve the following JSON on GET /api/v1/network/nodes:
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{"ip_address_v4": "<tarpit-ip>", "port": 50211}]
  }],
  "links": {"next": null}
}

# 3. Start the pinger with network=other pointing at the spoofed mirror REST URL.
#    fetchMirrorNodeNetwork accepts the response (non-empty host, non-zero port).
#    hiero.ClientForNetwork builds the client pointing at <tarpit-ip>:50211.
#    Every Execute() call in submitWithRetry blocks indefinitely.
#    /tmp/alive is still updated every 15s — pod appears healthy.
```

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L90-93)
```go
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("GET %s returned %s", url, resp.Status)
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/sdk_client.go (L22-22)
```go
		client = hiero.ClientForNetwork(netmap)
```

**File:** pinger/transfer.go (L23-33)
```go
	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		start := time.Now()
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```

**File:** pinger/main.go (L28-39)
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
```
