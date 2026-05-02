### Title
Non-Retryable DoS via Crafted Empty-Endpoint Mirror Node Response in `fetchMirrorNodeNetwork()`

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` silently filters out any `serviceEndpoint` where both `DomainName` and `IPAddressV4` are empty strings. When all endpoints are filtered, it returns `retry=false` (non-retryable), which causes `buildNetworkFromMirrorNodes()` to abort its entire retry loop on the very first attempt. Because `main()` calls `log.Fatalf` on the resulting error, the pinger process terminates permanently. An attacker who can control or intercept the mirror REST server's HTTP response can trigger this with a single crafted reply.

### Finding Description

**Exact code path:**

`pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 113–128:

```go
for _, ep := range n.ServiceEndpoints {
    host := strings.TrimSpace(ep.DomainName)
    if host == "" {
        host = strings.TrimSpace(ep.IPAddressV4)
    }
    if host == "" || ep.Port == 0 {
        continue          // ← silently drops the endpoint
    }
    addr := net.JoinHostPort(host, fmt.Sprintf("%d", ep.Port))
    network[addr] = nodeAccountId
}
```

After the loop:

```go
if len(network) == 0 {
    return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
    //              ^^^^^ non-retryable
}
```

Back in `buildNetworkFromMirrorNodes()` (lines 58–61):

```go
lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
if !retry || attempt == attempts {
    break   // ← exits retry loop immediately when retry=false
}
```

And in `main.go` line 43:

```go
log.Fatalf("client error: %v", err)   // ← process terminates
```

**Root cause / failed assumption:** The code assumes that receiving a structurally valid JSON response with no usable host fields is a permanent, non-transient condition and therefore marks it non-retryable. This assumption is wrong: an attacker can deliberately craft exactly this response. The retry mechanism — configured up to 10 attempts via `mirrorNodeClientMaxRetries` — is completely bypassed because `retry=false` causes the loop to break on the first attempt regardless of the configured retry count.

**Exploit flow:**
1. Attacker intercepts or serves the mirror REST endpoint (see Likelihood).
2. Returns HTTP 200 with valid JSON where every node's `service_endpoints` array contains entries with `"domain_name": ""` and `"ip_address_v4": ""` (but a non-zero port, so the node itself is not skipped for other reasons).
3. Lines 114–119 filter every endpoint; `network` map stays empty.
4. Line 128 returns `(nil, false, error)`.
5. Line 59 evaluates `!retry` → `true` → `break`; all configured retries are skipped.
6. `buildNetworkFromMirrorNodes()` returns the error to `newClient()`.
7. `main()` calls `log.Fatalf` → process exits.

**Why existing checks are insufficient:**
- The HTTP status-code check (lines 90–93) only retries on 429/5xx; a 200 response bypasses it entirely.
- The JSON decode check (lines 96–98) only catches malformed JSON; structurally valid JSON with empty strings passes.
- The `mirrorNodeClientMaxRetries` configuration has no effect because the non-retryable flag short-circuits the loop before any retry occurs.
- There is no TLS certificate pinning; the `http.Client` is constructed with only a timeout (line 46), relying solely on the OS trust store.

### Impact Explanation

The pinger process terminates via `log.Fatalf`, permanently halting its function of submitting periodic transfers to verify Hiero network health. The `/tmp/ready` readiness file is never written (line 47 is never reached), so Kubernetes readiness probes also fail, preventing the pod from receiving traffic. The attack requires only one successful HTTP response and is immediately effective with no recovery path short of a manual restart — and if the attacker continues to serve the malicious response, every restart will also fail.

### Likelihood Explanation

The default example mirror REST URL in `config.go` line 37 is `http://mirror-rest:5551` — plaintext HTTP. In any deployment using HTTP (common in internal Kubernetes clusters), a network-adjacent attacker (compromised sidecar, ARP/DNS poisoning on the cluster network, or a rogue service registered under the same DNS name) can perform a trivial MITM with no credentials required. Even with HTTPS, DNS poisoning or a compromised mirror REST server achieves the same result. The crafted payload is trivial to construct, the attack is repeatable on every restart, and no authentication or signing of the mirror node response is required or checked anywhere in the code.

### Recommendation

1. **Make the empty-network condition retryable.** Change line 128 to return `retry=true`:
   ```go
   return nil, true, fmt.Errorf("no usable service_endpoints found from %s", url)
   ```
   This ensures transient or malicious empty responses are retried up to the configured limit rather than causing immediate fatal failure.

2. **Do not use `log.Fatalf` for recoverable initialization errors.** Replace the fatal call in `main.go` with a retry loop or a supervised restart strategy so a single bad response cannot permanently kill the process.

3. **Enforce HTTPS and validate TLS.** Reject plaintext HTTP mirror REST URLs at config validation time, or add explicit TLS configuration with certificate pinning to prevent MITM.

4. **Add a minimum-node sanity check.** Require at least N usable endpoints (e.g., N≥1 from at least M distinct nodes) before accepting the response as valid, and treat any response falling below the threshold as retryable.

### Proof of Concept

**Preconditions:** Attacker can serve or intercept HTTP responses to the mirror REST URL (e.g., plaintext `http://mirror-rest:5551` in a Kubernetes cluster via DNS spoofing or a rogue service).

**Steps:**

1. Stand up a mock HTTP server that always responds to `GET /api/v1/network/nodes` with:
   ```json
   {
     "nodes": [
       {
         "node_account_id": "0.0.3",
         "service_endpoints": [
           {"domain_name": "", "ip_address_v4": "", "port": 50211}
         ]
       }
     ],
     "links": {"next": null}
   }
   ```
2. Configure the pinger with `HIERO_MIRROR_PINGER_NETWORK=other` and `HIERO_MIRROR_PINGER_REST=http://<mock-server>`.
3. Start the pinger.
4. **Observed:** `fetchMirrorNodeNetwork()` returns `(nil, false, "no usable service_endpoints found …")` on the first attempt; `buildNetworkFromMirrorNodes()` breaks immediately; `main()` logs `client error: attempt 1/11: …` and exits with status 1. The `/tmp/ready` file is never created.
5. **Expected (correct behavior):** The error should be retried up to `mirrorNodeClientMaxRetries` times before giving up, and the process should not terminate fatally on a transient or adversarial response.