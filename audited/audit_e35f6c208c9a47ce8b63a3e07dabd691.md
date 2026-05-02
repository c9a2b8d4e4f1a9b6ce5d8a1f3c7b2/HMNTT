### Title
Unauthenticated Mirror Node Response Enables Arbitrary gRPC Endpoint Injection via Unvalidated Port and Host Fields

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` decodes the mirror node REST response into `serviceEndpoint.Port` (typed `int`) with no range validation beyond `!= 0`, and accepts any string for `DomainName`/`IPAddressV4` without allowlist or format checks. Because the HTTP client is constructed with no TLS enforcement and the default configured URL is plaintext HTTP, a network-positioned attacker who can intercept or spoof the mirror node response can inject semantically crafted JSON — including out-of-range port values (e.g., `-1`, `99999`) and attacker-controlled hostnames — causing `net.JoinHostPort()` to build addresses that route all subsequent Hiero transactions to attacker-controlled gRPC services.

### Finding Description

**Code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–131.

The struct at line 33 declares `Port int` with no constraint annotation: [1](#0-0) 

The HTTP client at line 46 is a bare `http.Client` with no TLS configuration, and the default `mirrorRest` URL documented in `config.go` line 37 is explicitly `http://mirror-rest:5551` (plaintext): [2](#0-1) [3](#0-2) 

After decoding at line 96, the only guard on the endpoint is: [4](#0-3) 

Any non-zero port — including `-1`, `65536`, `99999` — passes this check. The address is then assembled unconditionally: [5](#0-4) 

**Root cause:** Go's `encoding/json` decodes JSON numbers into `int` using `strconv.ParseInt` with the platform word size (64-bit). Numbers like `-1` or `99999` are valid `int64` values and decode without error. True int64 overflow would return a decode error, but semantically invalid port values (negative, > 65535) are silently accepted. Combined with no host allowlist and a plaintext HTTP transport, the entire network map fed to the Hiero SDK is attacker-controlled.

**Why existing checks fail:** The `ep.Port == 0` guard (line 118) only rejects the zero value. There is no `1 ≤ port ≤ 65535` range check, no IP/domain allowlist, no TLS certificate pinning, and no HTTPS enforcement on the mirror node HTTP client.

### Impact Explanation

The `network` map returned by `fetchMirrorNodeNetwork()` is passed directly to the Hiero SDK as the consensus node address book. Every transaction submitted by the pinger — including signed transfers carrying the operator's private key material in the transaction envelope — is sent to the gRPC endpoints in this map. An attacker who controls those endpoints can:

- Receive and log all submitted transactions (including signed payloads).
- Return crafted gRPC responses (e.g., fake `SUCCESS` receipts) causing the pinger to believe transfers succeeded when they did not.
- Silently drop transactions, causing liveness failures that are invisible to the operator.

Severity: **High** — full transaction interception and manipulation of a live network health-check service.

### Likelihood Explanation

**Precondition:** The attacker must be able to intercept or spoof the HTTP response from the mirror node REST endpoint. This is achievable by:

1. **DNS poisoning** of the mirror node hostname — a well-known, unprivileged network attack requiring no credentials.
2. **On-path MITM** (ARP spoofing, BGP hijack, rogue Wi-Fi) against a plaintext HTTP connection — the default configuration uses `http://`.
3. **Compromised or malicious mirror node** — the mirror node is a third-party service; the pinger places unconditional trust in its response.

No authentication, no TLS certificate validation, and no response signing are required of the attacker. The attack is repeatable on every startup of the pinger (and on every retry cycle). Likelihood: **Medium-High** for deployments using the default HTTP URL.

### Recommendation

1. **Enforce HTTPS** for the mirror node client. Reject any `mirrorRest` URL that does not use the `https://` scheme, or configure the `http.Client` with a TLS config that requires certificate verification.
2. **Validate port range** after decoding: reject any `ep.Port` outside `[1, 65535]`.
3. **Validate host format**: reject entries where `DomainName`/`IPAddressV4` do not match expected patterns (e.g., known network node IP ranges or a configured allowlist).
4. **Pin or verify the mirror node TLS certificate** to prevent MITM even against HTTPS.

### Proof of Concept

1. Stand up a DNS server that resolves the mirror node hostname (e.g., `mirror-rest`) to an attacker-controlled IP.
2. On the attacker-controlled IP, serve the following JSON at `GET /api/v1/network/nodes`:
   ```json
   {
     "nodes": [{
       "node_account_id": "0.0.3",
       "service_endpoints": [{
         "domain_name": "attacker.example.com",
         "ip_address_v4": "",
         "port": 50211
       }]
     }],
     "links": {"next": null}
   }
   ```
3. Start the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://mirror-rest:5551`.
4. The pinger calls `fetchMirrorNodeNetwork()`, decodes the crafted response, passes the `ep.Port == 0` check (port is 50211), and builds `network["attacker.example.com:50211"] = 0.0.3`.
5. All subsequent Hiero SDK transactions are submitted to `attacker.example.com:50211`.
6. Substitute `port: -1` or `port: 99999` to demonstrate that out-of-range values also pass the guard and produce malformed addresses (`attacker.example.com:-1`) that the SDK will attempt to dial.

### Citations

**File:** pinger/mirror_node_client.go (L30-34)
```go
type serviceEndpoint struct {
	DomainName  string `json:"domain_name"`
	IPAddressV4 string `json:"ip_address_v4"`
	Port        int    `json:"port"`
}
```

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L118-119)
```go
			if host == "" || ep.Port == 0 {
				continue
```

**File:** pinger/mirror_node_client.go (L122-123)
```go
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
			network[addr] = nodeAccountId
```

**File:** pinger/config.go (L37-37)
```go
	flag.StringVar(&cfg.mirrorRest, "mirror-rest", envOr("HIERO_MIRROR_PINGER_REST", ""), "mirror node REST base URL (required for other), e.g. http://mirror-rest:5551")
```
