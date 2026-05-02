The code references in the claim are accurate. Let me verify the exact lines before rendering a verdict.

**Verified facts from the actual code:**

- `Port int` with no bounds — confirmed at [1](#0-0) 
- The only guard is `ep.Port == 0` — confirmed at [2](#0-1) 
- Raw integer is formatted and passed to `net.JoinHostPort` — confirmed at [3](#0-2) 
- The resulting map is passed directly to `hiero.ClientForNetwork` — confirmed at [4](#0-3) 
- The only empty-map guard fires only when `len(network) == 0` — confirmed at [5](#0-4) 

All five code references in the claim are exact and correct. The root cause, exploit path, and impact are all technically sound.

---

Audit Report

## Title
Missing Port Range Validation in `fetchMirrorNodeNetwork` Allows Malformed gRPC Addresses via Attacker-Controlled Mirror Endpoint

## Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` deserializes `port` from the mirror REST response into a plain Go `int` with no range validation beyond a zero-check. An attacker who can serve an arbitrary HTTP response from the configured mirror REST endpoint can supply port values such as `-1` or `99999`, which pass the only guard (`ep.Port == 0`), get formatted into syntactically invalid address strings, and are fed directly into the Hiero SDK network map — causing the pinger to permanently fail to submit transactions.

## Finding Description
`serviceEndpoint.Port` is declared as a plain `int`:

```go
// pinger/mirror_node_client.go, line 33
Port int `json:"port"`
```

`json.Unmarshal` will decode any JSON integer (including `-1`, `99999`, `-32768`) into this field without error. The only filter applied before use is:

```go
// lines 118–119
if host == "" || ep.Port == 0 {
    continue
}
```

This rejects only the zero value. Every other integer — including all negative values and all values above 65535 — passes through. The raw integer is then serialised and passed to `net.JoinHostPort`:

```go
// line 122
addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
```

`net.JoinHostPort` accepts any string as the port component and produces addresses like `"10.0.0.1:-1"` or `"node.example.com:99999"`. These are inserted into the `network` map and returned to `newClient`, which passes them verbatim to `hiero.ClientForNetwork(netmap)`.

## Impact Explanation
When the SDK client is initialised with a network map whose every entry has an invalid port string, every gRPC dial attempt fails immediately (the OS rejects the address before a TCP SYN is sent). The pinger can never submit a transaction. Because `buildNetworkFromMirrorNodes` returns a non-empty map, the length check at line 127 does not fire, no error is surfaced at startup, and the client is created successfully — then silently fails on every tick. This results in total operational shutdown of the pinger with no self-healing unless the process is restarted against a clean mirror endpoint.

## Likelihood Explanation
The precondition is that the attacker can serve an HTTP response to the pinger's mirror REST URL. This is realistic in several scenarios:

1. The `mirrorRest` URL uses plain HTTP — a network-adjacent attacker (same LAN, cloud VPC, or BGP peer) can MITM the connection with no credentials.
2. The mirror node server itself is compromised or misconfigured.
3. In a Kubernetes/Docker deployment, internal service DNS resolves to an attacker-controlled pod (e.g. via a compromised sidecar or DNS spoofing).

No credentials, no special privileges within the pinger system, and no prior knowledge of the operator key are required. The attack is fully repeatable: every time the pinger restarts and calls `buildNetworkFromMirrorNodes`, it re-fetches and re-poisons the network map.

## Recommendation
Replace the `ep.Port == 0` guard with a proper TCP port range check:

```go
if host == "" || ep.Port < 1 || ep.Port > 65535 {
    continue
}
```

Optionally, change `Port` to `uint16` so the JSON decoder itself rejects out-of-range values at unmarshal time, though a uint16 would still accept `0` and the explicit check remains necessary.

## Proof of Concept
Serve the following JSON from the configured mirror REST endpoint:

```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "ip_address_v4": "10.0.0.1", "port": -1 }
      ]
    }
  ],
  "links": { "next": null }
}
```

`fetchMirrorNodeNetwork` will:
1. Parse `port: -1` into `ep.Port = -1`.
2. Pass the `ep.Port == 0` guard (since `-1 != 0`).
3. Produce `addr = "10.0.0.1:-1"` via `net.JoinHostPort`.
4. Return `{"10.0.0.1:-1": AccountID{0,0,3}}` as a non-empty map.
5. `newClient` calls `hiero.ClientForNetwork({"10.0.0.1:-1": ...})` — client is created without error.
6. Every subsequent gRPC dial to `10.0.0.1:-1` fails at the OS level; the pinger cannot submit any transaction.

### Citations

**File:** pinger/mirror_node_client.go (L30-34)
```go
type serviceEndpoint struct {
	DomainName  string `json:"domain_name"`
	IPAddressV4 string `json:"ip_address_v4"`
	Port        int    `json:"port"`
}
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

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```

**File:** pinger/sdk_client.go (L18-22)
```go
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		client = hiero.ClientForNetwork(netmap)
```
