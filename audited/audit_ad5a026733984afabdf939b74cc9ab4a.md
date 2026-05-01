### Title
Missing IP Address Range Validation in `fetchMirrorNodeNetwork` Allows Injection of Multicast/Reserved Addresses into gRPC Network Map

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` accepts any non-empty string from `ip_address_v4` in a mirror node response as a valid gRPC host, with no validation against reserved, multicast, loopback, or link-local address ranges. An attacker who can influence the mirror node HTTP response (e.g., via MITM on a plaintext HTTP connection, DNS hijacking, or operating a malicious mirror node) can inject a multicast address such as `224.0.0.1` that passes all existing checks and is fed directly into the Hiero SDK's network map, causing all gRPC connection attempts for that node to produce undefined network-layer behavior and disrupting smart contract transaction routing.

### Finding Description
In `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()` (lines 113–124) iterates over `ServiceEndpoints` from the mirror node JSON response and applies exactly two guards before accepting a host:

```go
host := strings.TrimSpace(ep.DomainName)
if host == "" {
    host = strings.TrimSpace(ep.IPAddressV4)
}
if host == "" || ep.Port == 0 {
    continue
}
addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
network[addr] = nodeAccountId
```

The only rejection criteria are: empty host string, or zero port. There is no call to `net.ParseIP`, no check against `ip.IsMulticast()`, `ip.IsLoopback()`, `ip.IsLinkLocalUnicast()`, `ip.IsPrivate()`, or any other reserved-range predicate. A value of `"224.0.0.1"` is a non-empty string with a valid port, so it passes both guards unconditionally and is inserted into the `network` map returned to the SDK.

The HTTP client is constructed with no TLS configuration beyond a timeout:
```go
httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```
There is no certificate pinning, no enforced HTTPS scheme check on `cfg.mirrorRest`, and no response signature verification. A network-level attacker positioned between the pinger and the mirror node REST endpoint (or one who hijacks DNS for the mirror node hostname) can serve a crafted JSON body containing `"ip_address_v4": "224.0.0.1"` for one or more nodes.

**Exploit flow:**
1. Attacker intercepts or spoofs the HTTP GET to `/api/v1/network/nodes`.
2. Response body contains one or more node entries with `"ip_address_v4": "224.0.0.1"` and a non-zero port (e.g., `50211`).
3. `fetchMirrorNodeNetwork` accepts the address; `net.JoinHostPort` produces `"224.0.0.1:50211"`.
4. This address is stored in the `network` map and passed to the Hiero SDK.
5. The SDK attempts TCP/gRPC dial to `224.0.0.1:50211`. TCP to a multicast address is undefined at the IP layer — most OS kernels will either immediately return `ENETUNREACH`/`EADDRNOTAVAIL`, or silently drop the SYN, causing the dial to hang until timeout.
6. If all injected entries replace legitimate nodes, the pinger cannot submit any smart contract transactions.

### Impact Explanation
Smart contract transaction routing through the pinger is fully disrupted for any node whose endpoint is replaced with a multicast address. Because the `network` map is the sole source of gRPC targets for the SDK, injecting multicast addresses for all nodes causes every transaction attempt to fail with a network-layer error. There are no funds directly at risk, but the pinger's liveness monitoring and transaction submission capability are rendered non-functional for the duration of the attack, matching the stated Medium severity (unintended smart contract behavior, no direct fund loss).

### Likelihood Explanation
The precondition — controlling the mirror node HTTP response — is achievable without any privileged access to the pinger host or the Hiero network:
- If `cfg.mirrorRest` uses `http://` (no TLS), any on-path network attacker can inject a response.
- DNS hijacking of the mirror node hostname requires no credentials on the target system.
- A misconfigured or malicious mirror node operator can serve arbitrary node lists.
The attack is repeatable on every polling cycle and requires only standard HTTP interception tooling.

### Recommendation
After parsing `ep.IPAddressV4` and before inserting into the network map, validate the parsed IP against all reserved ranges:

```go
if ip := net.ParseIP(host); ip != nil {
    if ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
       ip.IsUnspecified() || ip.IsLinkLocalMulticast() {
        continue
    }
}
```

Additionally:
- Enforce HTTPS for `cfg.mirrorRest` and validate the TLS certificate chain.
- Reject port values outside the expected gRPC range (e.g., only allow `50211`/`50212` or a configurable allowlist).
- Consider cross-checking returned node account IDs against a locally configured trusted set.

### Proof of Concept
1. Stand up a local HTTP server that responds to `GET /api/v1/network/nodes` with:
```json
{
  "nodes": [{
    "node_account_id": "0.0.3",
    "service_endpoints": [{"ip_address_v4": "224.0.0.1", "domain_name": "", "port": 50211}]
  }],
  "links": {"next": null}
}
```
2. Configure the pinger with `mirrorRest` pointing to this server (HTTP, no TLS).
3. Run the pinger. `fetchMirrorNodeNetwork` returns `{"224.0.0.1:50211": AccountID{0,0,3}}` with no error.
4. The Hiero SDK attempts `grpc.Dial("224.0.0.1:50211")`; the TCP connection fails or hangs indefinitely.
5. All smart contract transaction submissions via the pinger fail for the duration the injected response is served.