### Title
Mirror Node Response Poisoning Injects Dead gRPC Endpoints, Permanently Stalling All Pinger Transactions

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` accepts any syntactically valid `host:port` string from the mirror node REST response without validating reachability or address legitimacy. Because `newClient()` builds the Hiero SDK client exactly once at startup and the main loop reuses it forever, an attacker who can control the mirror node REST response at startup time can inject unreachable endpoints (e.g., `0.0.0.0:50211`), causing every subsequent `Execute(client)` call to time out indefinitely.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go` lines 100–131 — `fetchMirrorNodeNetwork()`:

```go
network := make(map[string]hiero.AccountID)

for _, n := range payload.Nodes {
    if n.NodeAccountID == "" { continue }
    nodeAccountId, err := hiero.AccountIDFromString(n.NodeAccountID)
    if err != nil { continue }

    for _, ep := range n.ServiceEndpoints {
        host := strings.TrimSpace(ep.DomainName)
        if host == "" { host = strings.TrimSpace(ep.IPAddressV4) }
        if host == "" || ep.Port == 0 { continue }          // ← only guard

        addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
        network[addr] = nodeAccountId                        // ← no reachability check
    }
}

if len(network) == 0 {                                       // ← only catches empty map
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
}
return network, false, nil
``` [1](#0-0) 

**Root cause:** The function's only content-level guards are:
1. Skip entries with empty `NodeAccountID` or unparseable account IDs.
2. Skip endpoints where `host == ""` or `port == 0`.
3. Reject the entire response only if the resulting map is empty.

None of these checks prevent an attacker from supplying syntactically valid but permanently unreachable addresses such as `0.0.0.0:50211`, `192.0.2.1:50211` (TEST-NET), or any black-hole IP. Such addresses pass all three guards and populate the network map.

**Client is built once and never refreshed:**

`pinger/sdk_client.go` lines 18–22 call `buildNetworkFromMirrorNodes()` and immediately pass the result to `hiero.ClientForNetwork(netmap)`:

```go
netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
if err != nil { return nil, err }
client = hiero.ClientForNetwork(netmap)
``` [2](#0-1) 

`pinger/main.go` line 41 calls `newClient(cfg)` once at startup and stores the result. The ticker loop (lines 54–70) reuses the same `client` pointer on every tick with no mechanism to rebuild it from the mirror node:

```go
client, err := newClient(cfg)
...
for {
    select {
    case <-ticker.C:
        if err := submitWithRetry(ctx, client, cfg); err != nil { ... }
    }
}
``` [3](#0-2) 

**Exploit flow:**

1. Attacker intercepts or replaces the mirror node REST response at `GET /api/v1/network/nodes`.
2. Crafted response contains syntactically valid `node_account_id` values (e.g., `0.0.3`) and `service_endpoints` with `ip_address_v4: "0.0.0.0"` and `port: 50211`.
3. `fetchMirrorNodeNetwork()` accepts all entries — `host` is `"0.0.0.0"`, port is non-zero, so the skip condition is not triggered. The map is non-empty, so the final guard passes.
4. `hiero.ClientForNetwork({"0.0.0.0:50211": AccountID{0,0,3}})` creates a client pointing exclusively at dead endpoints.
5. Every `cryptoTransfer.Execute(client)` in `submitWithRetry()` blocks until the SDK's gRPC deadline, then returns a timeout error.
6. The pinger logs failures and retries, but since the client is never rebuilt, all retries also time out. The operator account cannot send HBAR via the pinger for the lifetime of the process. [4](#0-3) 

**Why existing checks are insufficient:**

| Check | Location | What it catches | What it misses |
|---|---|---|---|
| `host == "" \|\| ep.Port == 0` | line 118 | Blank host or zero port | Any non-empty, non-zero but unreachable address |
| `len(network) == 0` | line 127 | Completely empty response | Non-empty map of dead endpoints |
| HTTP status check | lines 90–93 | Non-2xx HTTP responses | Valid 200 responses with poisoned content | [5](#0-4) 

### Impact Explanation

The pinger's sole purpose is to periodically execute HBAR transfers from the operator account to verify network liveness. With a poisoned network map, every `Execute(client)` call times out. Because the client is never refreshed, the pinger cannot execute any transaction for the entire lifetime of the process. The operator account's HBAR cannot be moved via the pinger until the process is restarted against a clean mirror node response. This is a complete, persistent denial-of-service against the pinger's core function. The liveness heartbeat (`/tmp/alive`) continues to be written (it is independent of transaction success), so the Kubernetes liveness probe does not restart the pod, making the freeze self-sustaining. [6](#0-5) 

### Likelihood Explanation

This vulnerability is only reachable when `HIERO_MIRROR_PINGER_NETWORK=other`, which is the custom-network deployment mode. In that mode, the mirror node REST URL is operator-configured and the default example in `config.go` uses a plain `http://` scheme:

```
e.g. http://mirror-rest:5551
``` [7](#0-6) 

Over a plain HTTP connection, any network-adjacent attacker (same LAN, compromised router, ARP/DNS poisoning) can inject a crafted response with zero special privileges on the target host. The attack is:
- **Repeatable**: The poisoned client persists until process restart.
- **Stealthy**: The liveness probe keeps passing; only the transfer logs reveal failures.
- **Low-skill**: Crafting a valid JSON `nodesEnvelope` with dead endpoints requires no cryptographic capability.

### Recommendation

1. **Validate endpoint addresses before accepting them.** Reject entries where the resolved IP is `0.0.0.0`, a loopback address (`127.x.x.x`), or an IANA-reserved/documentation range. Use `net.ParseIP()` and check `ip.IsUnspecified()`, `ip.IsLoopback()`, `ip.IsLinkLocalUnicast()`.

2. **Probe at least one endpoint before accepting the network map.** Perform a TCP dial with a short timeout (e.g., 2 s) against each candidate address; discard addresses that refuse or time out. Require at least one live endpoint before returning the map.

3. **Enforce HTTPS for the mirror node REST URL.** Reject `http://` schemes in `loadConfig()` to prevent trivial MITM injection.

4. **Periodically refresh the network map.** Rebuild the client (or call `client.SetNetwork()`) on a background ticker so that a poisoned startup state can be corrected without a process restart.

5. **Fail the readiness probe on a poisoned map.** If `buildNetworkFromMirrorNodes` returns a map that fails the probe-dial step, do not write `/tmp/ready`, causing Kubernetes to restart the pod rather than silently running a broken pinger.

### Proof of Concept

**Preconditions:**
- Pinger deployed with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551` (HTTP, not HTTPS).
- Attacker has network-adjacent position (same subnet, or DNS control for `mirror-rest`).

**Steps:**

1. Stand up a rogue HTTP server that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "ip_address_v4": "0.0.0.0", "port": 50211 }
      ]
    }
  ],
  "links": {}
}
```

2. Redirect DNS for `mirror-rest` (or ARP-spoof the mirror node IP) to the rogue server.

3. Start (or restart) the pinger. `fetchMirrorNodeNetwork()` fetches from the rogue server. The response passes all guards: `node_account_id` is non-empty and parseable, `host = "0.0.0.0"` is non-empty, `port = 50211` is non-zero, `len(network) = 1 > 0`.

4. `hiero.ClientForNetwork({"0.0.0.0:50211": {0,0,3}})` is called. The pinger writes `/tmp/ready` and enters the ticker loop.

5. Every tick, `cryptoTransfer.Execute(client)` attempts to connect to `0.0.0.0:50211`, times out, and logs a failure. No HBAR is ever transferred. The liveness probe continues to pass (heartbeat goroutine is unaffected), so Kubernetes does not restart the pod.

6. The freeze persists indefinitely until an operator manually restarts the pinger against a legitimate mirror node.

### Citations

**File:** pinger/mirror_node_client.go (L100-131)
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

	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}

	return network, false, nil
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
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

**File:** pinger/main.go (L41-70)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}

	// Mark readiness for exec probe (creates /tmp/ready)
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}

	log.Printf("Starting transfer ticker: every %s, %d tinybar from %s -> %s on %s",
		cfg.interval, cfg.amountTinybar, cfg.operatorID, cfg.toAccountID, cfg.network)

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Shutting down")
			return
		case <-ticker.C:
			if err := submitWithRetry(ctx, client, cfg); err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				log.Printf("transfer failed: %v", err)
			}
		}
	}
```

**File:** pinger/transfer.go (L29-33)
```go
		cryptoTransfer := hiero.NewTransferTransaction().
			AddHbarTransfer(client.GetOperatorAccountID(), hiero.HbarFromTinybar(-cfg.amountTinybar)).
			AddHbarTransfer(toID, hiero.HbarFromTinybar(cfg.amountTinybar))

		resp, err := cryptoTransfer.Execute(client)
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
