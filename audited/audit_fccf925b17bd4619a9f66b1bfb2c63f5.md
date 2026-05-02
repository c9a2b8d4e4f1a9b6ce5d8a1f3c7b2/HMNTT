### Title
Negative Port Values Bypass Validation in `fetchMirrorNodeNetwork`, Poisoning the Network Map with Invalid Addresses

### Summary
In `pinger/mirror_node_client.go`, the `fetchMirrorNodeNetwork()` function deserializes `port` into a signed `int` field and only rejects entries where `ep.Port == 0`. An attacker who controls the mirror node HTTP response can supply negative port values (e.g., `-1`), which pass the zero-check, get formatted via `fmt.Sprintf("%d", ep.Port)` into strings like `"-1"`, and are stored in the returned network map as syntactically-formed but semantically invalid addresses. The function returns no error and a non-empty map, so the pinger proceeds with a fully poisoned node list and cannot connect to any real Hedera network node.

### Finding Description
**File:** `pinger/mirror_node_client.go`
**Function:** `fetchMirrorNodeNetwork()`, lines 74–132

**Root cause — unsigned assumption on a signed field:**

```go
// line 33
Port int `json:"port"`   // signed — accepts any int64 value from JSON
```

**Insufficient guard — only zero is excluded:**

```go
// line 118
if host == "" || ep.Port == 0 {
    continue          // negative ports (-1, -65535, …) are NOT skipped
}
```

**Poisoned address construction:**

```go
// line 122
addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
// ep.Port = -1  →  addr = "1.2.3.4:-1"
network[addr] = nodeAccountId   // stored without error
```

**Silent success path:**

```go
// lines 127-129
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found …")
}
return network, false, nil   // returns successfully with all-invalid addresses
```

If every `service_endpoint` entry carries a negative port, `len(network) > 0` is satisfied, no error is returned, and the caller receives a map whose every key is an invalid address.

### Impact Explanation
The pinger's entire purpose is to dial Hedera consensus nodes and measure liveness. With a poisoned network map it dials addresses like `"0.0.3:-1"` for every node, all of which fail at the TCP layer. The pinger reports no nodes reachable, effectively disabling the monitoring service. Because `fetchMirrorNodeNetwork` signals success, the retry/backoff logic in `buildNetworkFromMirrorNodes` is not triggered — the bad map is used as-is for the lifetime of the run.

### Likelihood Explanation
The precondition is controlling the mirror node HTTP response. This is achievable by:
1. **HTTP (non-TLS) deployment** — a network-adjacent attacker can inject a crafted response with no special privileges on the target host.
2. **DNS poisoning / BGP hijack** — redirects the mirror node hostname to an attacker server.
3. **Compromised or malicious mirror node operator** — the mirror node itself is an external service; its operator is not the same trust domain as the pinger operator.

No authentication of the mirror node response is performed in the code. The attack is repeatable on every restart or network refresh cycle.

### Recommendation
Replace the signed `int` with `uint16` (or add an explicit range check) so that only valid TCP port numbers are accepted:

```go
// Option A – type-level fix
type serviceEndpoint struct {
    DomainName  string `json:"domain_name"`
    IPAddressV4 string `json:"ip_address_v4"`
    Port        uint16 `json:"port"`   // JSON decoder rejects negatives
}

// Option B – explicit range guard (keep int for JSON flexibility)
if host == "" || ep.Port <= 0 || ep.Port > 65535 {
    continue
}
```

Either change ensures that negative values and out-of-range values are rejected before the address is constructed and inserted into the network map.

### Proof of Concept
1. Stand up an HTTP server that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [
      {"ip_address_v4": "1.2.3.4", "port": -1}
    ]
  }],
  "links": {"next": null}
}
```
2. Point `cfg.mirrorRest` at this server (or MITM an HTTP mirror node URL).
3. Run the pinger. `fetchMirrorNodeNetwork` returns `{"1.2.3.4:-1": AccountID{0,0,3}}` with `err == nil`.
4. The SDK attempts to dial `1.2.3.4:-1`; every dial fails with "invalid port".
5. The pinger reports all nodes unreachable for the entire session, with no retry triggered, because the function reported success. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** pinger/mirror_node_client.go (L33-33)
```go
	Port        int    `json:"port"`
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

**File:** pinger/mirror_node_client.go (L127-131)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}

	return network, false, nil
```
