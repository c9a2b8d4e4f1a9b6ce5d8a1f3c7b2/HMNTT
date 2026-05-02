### Title
Unvalidated Port Values in Mirror Node Response Allow Network Map Poisoning via MITM

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches consensus node addresses over plain HTTP with no TLS enforcement and no port-range validation. An attacker who can intercept or spoof the HTTP response (MITM on the unencrypted channel, DNS hijack, or a compromised mirror node) can return `service_endpoints` with arbitrary `port` values, causing the pinger to build a `netmap` of entirely unreachable addresses and permanently fail to submit any transaction.

### Finding Description

**Code path:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 113–124.

```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {   // ← only guard: skip port 0
        continue
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId    // ← any port 1-65535 accepted
}
``` [1](#0-0) 

The sole validation is `ep.Port == 0`; every other value (1–65535) is accepted verbatim. The resulting `netmap` is passed directly to `hiero.ClientForNetwork(netmap)` with no further verification. [2](#0-1) 

The HTTP client is constructed with no TLS requirement:

```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
``` [3](#0-2) 

The default/example URL is `http://mirror-rest:5551` (plaintext HTTP). [4](#0-3) 

**Root cause:** The code assumes the mirror REST endpoint is trustworthy and returns valid, reachable ports. There is no allowlist of gRPC ports (50211/50212 are the standard Hedera ports), no TLS enforcement, and no post-build reachability check.

**Exploit flow:**
1. Attacker positions themselves to intercept the HTTP GET to `/api/v1/network/nodes` (MITM via ARP poisoning, DNS hijack, or rogue mirror node).
2. Attacker returns a well-formed JSON payload where every `service_endpoints[].port` is set to 65535 (or any firewalled/non-gRPC port), with valid-looking `ip_address_v4` or `domain_name` values.
3. `fetchMirrorNodeNetwork()` passes the `len(network) == 0` guard (the map is non-empty — it has entries, just with bad ports).
4. `hiero.ClientForNetwork(netmap)` builds a client targeting only unreachable addresses.
5. Every subsequent `submitWithRetry` call times out; the pinger never successfully submits a transaction. [5](#0-4) 

### Impact Explanation
The pinger is the liveness/health-check component for the Hiero network. A permanently broken pinger means:
- No transaction submissions → monitoring blackout; real network outages go undetected.
- The `/tmp/ready` readiness file is written before the ticker loop, so Kubernetes considers the pod healthy even while it silently fails every tick.
- Severity: **High** — complete loss of the monitoring function without any operator-visible crash. [6](#0-5) 

### Likelihood Explanation
- Requires network-level interception of an unencrypted HTTP channel — feasible via ARP spoofing on the same L2 segment, DNS poisoning, or a compromised internal mirror node.
- No application-level credentials are needed; the attack is purely at the HTTP/JSON layer.
- Repeatable: the pinger only calls `buildNetworkFromMirrorNodes` once at startup, so a single poisoned response is sufficient to permanently disable it for the lifetime of the pod.

### Recommendation
1. **Validate port ranges:** After parsing, reject any endpoint whose port is not in the expected gRPC range (e.g., 50211–50212, or a configurable allowlist). Add a check such as:
   ```go
   if ep.Port < 1 || ep.Port > 65535 || !isAllowedGRPCPort(ep.Port) {
       continue
   }
   ```
2. **Enforce TLS:** Require `https://` for `cfg.mirrorRest` and reject plain-HTTP URLs at config validation time.
3. **Pin or authenticate the mirror endpoint:** Use mutual TLS or a certificate pin so a MITM cannot substitute a rogue response.
4. **Post-build sanity check:** After constructing `netmap`, attempt a TCP dial to at least one address before returning; fail fast if none are reachable.

### Proof of Concept
```bash
# 1. Stand up a rogue HTTP server returning poisoned node data
cat > fake_mirror.json <<'EOF'
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        {"ip_address_v4": "35.237.200.180", "port": 65535}
      ]
    }
  ],
  "links": {"next": null}
}
EOF
python3 -m http.server 5551 &   # serves fake_mirror.json at /api/v1/network/nodes

# 2. Configure pinger to use the rogue mirror
export HIERO_MIRROR_PINGER_NETWORK=other
export HIERO_MIRROR_PINGER_REST=http://127.0.0.1:5551
export HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2
export HIERO_MIRROR_PINGER_OPERATOR_KEY=<valid_key>

# 3. Run pinger — it starts, writes /tmp/ready, but every transfer attempt
#    times out because 35.237.200.180:65535 is unreachable.
go run ./pinger/...
# Expected: repeated "transfer failed: ..." with connection timeout errors
```

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
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

**File:** pinger/mirror_node_client.go (L127-131)
```go
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

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```

**File:** pinger/main.go (L47-49)
```go
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```
