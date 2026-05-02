### Title
Unauthenticated Port Injection via Unvalidated Mirror Node Response Enables gRPC DoS

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` fetches node topology over a plain HTTP connection with no TLS enforcement and accepts any non-zero `serviceEndpoint.Port` value without validation. An attacker who can intercept or spoof the mirror node REST response (via DNS hijacking, ARP/BGP poisoning, or a rogue HTTP server) can inject a `nodesEnvelope` where every endpoint port is set to a non-gRPC port (e.g., 22, 3306), causing the Hiero SDK to attempt gRPC handshakes against those ports, which immediately reject or close the connection, silently preventing all transaction gossip.

### Finding Description
**Code location:** `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132.

**Root cause:** The HTTP client is constructed as a bare `&http.Client{Timeout: cfg.mirrorNodeClientTimeout}` with no TLS transport, no certificate pinning, and no scheme enforcement. The documented default value for `HIERO_MIRROR_PINGER_REST` is `http://mirror-rest:5551` (plaintext HTTP). After decoding the JSON body into `nodesEnvelope`, the only guard on `ep.Port` is:

```go
if host == "" || ep.Port == 0 {
    continue
}
``` [1](#0-0) 

Any non-zero port — including 22, 3306, 8080, 443 — passes this check and is unconditionally inserted into the network map:

```go
addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
network[addr] = nodeAccountId
``` [2](#0-1) 

That map is returned to `newClient()` and passed directly to `hiero.ClientForNetwork(netmap)`: [3](#0-2) 

**Exploit flow:**
1. Attacker poisons DNS for the mirror-rest hostname (or performs ARP/BGP MITM on the HTTP path).
2. Attacker's server responds with a valid-looking `nodesEnvelope` JSON where every `service_endpoints[].port` is `22` (SSH) or `3306` (MySQL).
3. `fetchMirrorNodeNetwork()` decodes the payload; all entries pass the `port != 0` check.
4. The full network map is built with attacker-controlled ports and handed to the SDK.
5. The SDK dials `host:22` or `host:3306` expecting gRPC; SSH/MySQL immediately sends a non-HTTP/2 banner or closes the connection.
6. Every transaction submission fails; gossip is completely blocked.

**Why existing checks are insufficient:**
- The `ep.Port == 0` guard only rejects the degenerate zero value; it does not enforce any allowlist of known gRPC ports (50211, 50212, etc.). [1](#0-0) 
- The HTTP client has no `Transport` override enforcing TLS, no `VerifyPeerCertificate`, and no scheme check on the URL. [4](#0-3) 
- The config layer accepts any URL string including `http://` with no warning or rejection. [5](#0-4) 

### Impact Explanation
A successful injection replaces the entire gRPC node map with attacker-controlled endpoints. The SDK has no fallback to a hardcoded or previously-cached topology. Every subsequent `submitWithRetry` call will fail because all gRPC dials target non-gRPC ports. This is a complete, persistent denial-of-service against transaction gossip for as long as the attacker controls DNS or the network path. Severity: **High** (full availability loss of the pinger's core function).

### Likelihood Explanation
The attack requires no credentials or privileged access to the pinger host. DNS hijacking is achievable by:
- A cloud-provider-level attacker who can manipulate internal DNS (e.g., a compromised sidecar in the same Kubernetes namespace).
- An attacker with access to the same L2 segment performing ARP poisoning.
- An external attacker exploiting a misconfigured public DNS record for the mirror-rest hostname.

The default example URL uses `http://` (plaintext), making network interception trivial compared to a TLS-protected endpoint. The attack is repeatable on every pinger restart or network refresh cycle.

### Recommendation
1. **Enforce HTTPS:** Reject any `mirrorRest` URL whose scheme is not `https` at config load time, or configure the HTTP client with a `Transport` that enforces TLS and certificate verification.
2. **Validate ports:** After decoding, reject any endpoint whose port is not in the known gRPC allowlist (e.g., `{50211, 50212}`):
   ```go
   var grpcPorts = map[int]bool{50211: true, 50212: true}
   if !grpcPorts[ep.Port] {
       continue
   }
   ```
3. **Validate IP/hostname:** Reject RFC-1918 or loopback addresses unless explicitly configured for a private network.
4. **Pin or verify the mirror node TLS certificate** to prevent MITM even over HTTPS.

### Proof of Concept
```bash
# 1. Stand up a rogue HTTP server returning a poisoned nodesEnvelope
cat > /tmp/nodes.json <<'EOF'
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        {"domain_name": "node0.example.com", "ip_address_v4": "", "port": 22}
      ]
    }
  ],
  "links": {"next": null}
}
EOF
python3 -m http.server 5551 --directory /tmp &

# 2. Poison DNS so mirror-rest resolves to attacker's machine (or set /etc/hosts)
echo "127.0.0.1 mirror-rest" >> /etc/hosts

# 3. Start pinger pointing at the rogue mirror node
HIERO_MIRROR_PINGER_NETWORK=other \
HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551 \
HIERO_MIRROR_PINGER_OPERATOR_ID=0.0.2 \
HIERO_MIRROR_PINGER_OPERATOR_KEY=<key> \
./pinger

# Result: SDK dials node0.example.com:22, receives SSH banner, gRPC handshake fails,
# all transfer attempts return connection errors — gossip is fully blocked.
```

### Citations

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L118-120)
```go
			if host == "" || ep.Port == 0 {
				continue
			}
```

**File:** pinger/mirror_node_client.go (L122-123)
```go
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
			network[addr] = nodeAccountId
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
