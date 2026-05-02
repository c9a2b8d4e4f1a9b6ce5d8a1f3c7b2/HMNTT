### Title
Unbounded Response Body in `fetchMirrorNodeNetwork` Enables OOM Crash via Oversized JSON

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` passes `resp.Body` directly to `json.NewDecoder(...).Decode(...)` with no byte-limit guard. An attacker who controls the mirror node REST endpoint can stream a multi-gigabyte valid JSON payload, causing the pinger process to exhaust heap memory and crash, halting all network health monitoring at zero economic cost.

### Finding Description
**Exact code path:**
`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, line 96:

```go
var payload nodesEnvelope
if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {   // line 96
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}
```

**Root cause:** `resp.Body` is an unbounded `io.ReadCloser`. No `io.LimitReader`, `http.MaxBytesReader`, or `Content-Length` pre-check is applied before handing it to the JSON decoder. The decoder materialises the entire decoded object graph in heap memory.

**Failed assumption:** The code assumes the mirror node endpoint is trusted and will return a small, well-formed response. This assumption is not enforced in code.

**Exploit flow:**
1. Attacker controls the mirror REST endpoint (see preconditions below).
2. Attacker's server responds with HTTP 200 and a valid JSON body containing an enormous `nodes` array — e.g., millions of `nodeEntry` objects with long strings in `domain_name`/`ip_address_v4` fields.
3. `json.NewDecoder(resp.Body).Decode(&payload)` reads and allocates the full decoded slice into heap.
4. Go runtime OOMs; the pinger process is killed by the OS.

**Why existing checks fail:**
- `http.Client{Timeout: cfg.mirrorNodeClientTimeout}` (default 10 s, line 46 of `mirror_node_client.go` / line 90–95 of `config.go`) limits *wall-clock time*, not bytes transferred. At 1 Gbps a 10-second window allows ~1.25 GB of data — more than enough to OOM a typical container.
- The HTTP status check (lines 90–93) only gates on non-2xx responses; a 200 with a giant body passes straight through.
- No `Content-Length` header inspection exists anywhere in the function.

### Impact Explanation
The pinger is the sole component responsible for continuous network health monitoring (submitting transfers and verifying liveness). Crashing it silently halts all monitoring. Because the crash is repeatable on every restart (the attacker's server keeps serving the oversized payload), the pinger cannot recover without operator intervention. Severity matches the stated scope: griefing / availability impact with no economic damage to network users.

### Likelihood Explanation
**Preconditions:**
- The vulnerability is reachable only when `network=other` is configured (`config.go` line 16: `mirrorRest string // only used when network=other`), pointing to a custom mirror REST URL.
- The attacker must control that URL — achievable via: (a) DNS hijacking of the configured hostname, (b) BGP hijacking, (c) a compromised or malicious mirror node operator, or (d) misconfiguration pointing to an attacker-owned server.

None of these require on-chain privileges. DNS/BGP attacks are well-documented and have been executed in the wild against blockchain infrastructure. The attack is repeatable with no rate-limiting cost to the attacker.

### Recommendation
Wrap `resp.Body` with a size-limiting reader before decoding:

```go
const maxResponseBytes = 4 * 1024 * 1024 // 4 MB — generous for any real node list

limited := io.LimitReader(resp.Body, maxResponseBytes+1)
var payload nodesEnvelope
if err := json.NewDecoder(limited).Decode(&payload); err != nil {
    return nil, false, fmt.Errorf("decode mirror nodes: %w", err)
}
// Optionally detect truncation:
// if n, _ := io.Copy(io.Discard, limited); n > 0 { /* response exceeded limit */ }
```

Alternatively use `http.MaxBytesReader(nil, resp.Body, maxResponseBytes)` which also causes `Decode` to return an error if the limit is exceeded. Add `import "io"` accordingly.

### Proof of Concept
1. Stand up an HTTP server that responds to any GET with:
   ```
   HTTP/1.1 200 OK
   Content-Type: application/json

   {"nodes":[{"node_account_id":"0.0.3","service_endpoints":[{"domain_name":"<4096-char string>","ip_address_v4":"","port":50211}]}<repeated 500,000 times>],"links":{}}
   ```
2. Configure the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<attacker-server>`.
3. Start the pinger. Observe it OOM-killed (exit code 137 / `signal: killed`) during startup before any health monitoring begins.
4. Restart the pinger — it crashes again immediately, permanently halting monitoring. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** pinger/config.go (L16-16)
```go
	mirrorRest string // only used when network=other
```

**File:** pinger/config.go (L90-95)
```go
	mirrorNodeClientTimeoutStr := envOr("HIERO_MIRROR_PINGER_MIRROR_NODE_CLIENT_TIMEOUT", "10s")
	flag.DurationVar(
		&cfg.mirrorNodeClientTimeout,
		"mirror-node-client-retry-timeout",
		toDuration(mirrorNodeClientTimeoutStr),
		"HTTP timeout for mirror node client requests (e.g. 2s, 10s)")
```
