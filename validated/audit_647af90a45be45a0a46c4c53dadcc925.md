All five code references are confirmed accurate against the actual source. Here is the audit report.

---

Audit Report

## Title
Rogue Mirror REST Server Can Crash-Loop the Pinger via All-Zero-Port `nodesEnvelope` Response

## Summary
When `network=other` is configured, the pinger fetches its consensus-node map from a mirror REST URL. If every `serviceEndpoint` in the response carries `port=0`, all entries are silently skipped, the resulting network map is empty, and `fetchMirrorNodeNetwork` returns `retry=false`. This bypasses all configured retries, causes `newClient()` to return an error, and `main()` calls `log.Fatalf()`, terminating the process. An attacker who can serve or intercept that HTTP response can keep the pinger in a permanent crash-loop.

## Finding Description

All five code references in the claim are confirmed accurate:

**1. `main.go:41-43` — `newClient()` failure is fatal**

`newClient` is called and any returned error immediately terminates the process via `log.Fatalf`. [1](#0-0) 

**2. `sdk_client.go:18-21` — `buildNetworkFromMirrorNodes` error propagates directly for `network=other`**

The `other` branch calls `buildNetworkFromMirrorNodes` and returns its error unwrapped to `newClient`, which returns it to `main`. [2](#0-1) 

**3. `mirror_node_client.go:113-124` — `port=0` silently skips every endpoint**

Inside the endpoint loop, any entry where `ep.Port == 0` is silently skipped via `continue`, adding nothing to the `network` map. [3](#0-2) 

**4. `mirror_node_client.go:127-129` — empty map returns `retry=false`**

After the loop, if `network` is empty, the function returns `nil, false, error` — the `false` signals "do not retry". [4](#0-3) 

**5. `mirror_node_client.go:59` — `retry=false` breaks the retry loop on the first attempt**

The retry loop breaks immediately when `!retry` is true, regardless of `mirrorNodeClientMaxRetries`. [5](#0-4) 

**Root cause:** The code treats "no usable endpoints" as a permanent, non-retryable error. This is a logic defect: a transient or malicious response with all `port=0` values is indistinguishable from a permanent misconfiguration, yet the code responds to both by immediately aborting all retries and propagating a fatal error.

## Impact Explanation
The pinger process exits via `log.Fatalf`. Under a container orchestrator (e.g., Kubernetes), the pod restarts and re-fetches the node list on every boot — re-triggering the same fatal path as long as the attacker continues serving the malicious payload. The `/tmp/ready` readiness file is never written (it is written only after `newClient` succeeds at line 47), so readiness/liveness probes permanently fail. No transfers are submitted, which is the sole operational purpose of the pinger. Severity: **Medium / Denial of Service**. [6](#0-5) 

## Likelihood Explanation
Preconditions: `network=other` must be configured (required for private/custom networks), and the attacker must be able to serve or intercept the HTTP response from `mirrorRest`. The example configuration uses plain `http://` with no TLS enforcement, making DNS poisoning or a compromised internal mirror node sufficient — no credentials or privileged access to the pinger host are needed. The attack is repeatable: every container restart re-fetches the node list, so the crash-loop persists indefinitely. [7](#0-6) 

## Recommendation

1. **Treat empty-network as retryable.** Change the `retry` return value at line 128 from `false` to `true` so that a response yielding zero usable endpoints is retried up to `mirrorNodeClientMaxRetries` times before giving up. [4](#0-3) 

2. **Enforce a minimum endpoint count.** After exhausting retries, if the network map is still empty, log a warning and optionally fall back to a statically configured node list rather than calling `log.Fatalf`.

3. **Enforce TLS on `mirrorRest`.** Reject `http://` URLs at config-load time when `network=other` to eliminate the plaintext interception vector.

4. **Degrade gracefully instead of fatally.** Replace `log.Fatalf` in `main` with a retry/backoff loop around `newClient` so a single bad response does not permanently terminate the process. [1](#0-0) 

## Proof of Concept

Serve the following JSON from the `mirrorRest` endpoint (or intercept the HTTP response via DNS poisoning / ARP spoofing on an unencrypted link):

```json
{
  "nodes": [
    {
      "node_account_id": "0.0.3",
      "service_endpoints": [
        { "domain_name": "node.example.com", "ip_address_v4": "", "port": 0 }
      ]
    }
  ],
  "links": { "next": null }
}
```

**Execution trace:**
1. `fetchMirrorNodeNetwork` decodes the payload; the single endpoint has `port=0` → `continue` at line 118–119 → `network` map remains empty.
2. Line 127–128: `len(network) == 0` → returns `nil, false, error("no usable service_endpoints …")`.
3. Line 59 in `buildNetworkFromMirrorNodes`: `!retry` is `true` → `break` on attempt 1, all retries skipped.
4. `buildNetworkFromMirrorNodes` returns the error to `newClient` (`sdk_client.go:19–20`).
5. `newClient` returns the error to `main` (`main.go:41–43`) → `log.Fatalf` → process exits.
6. Orchestrator restarts the pod → step 1 repeats → permanent crash-loop. [8](#0-7) [4](#0-3) [5](#0-4)

### Citations

**File:** pinger/main.go (L41-43)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
```

**File:** pinger/main.go (L47-49)
```go
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```

**File:** pinger/sdk_client.go (L17-21)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/mirror_node_client.go (L36-48)
```go
func buildNetworkFromMirrorNodes(ctx context.Context, cfg config) (map[string]hiero.AccountID, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.mirrorRest), "/")

	var url string
	if strings.HasSuffix(base, "/api/v1") {
		url = base + "/network/nodes"
	} else {
		url = base + "/api/v1/network/nodes"
	}

	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}

	attempts := max(cfg.mirrorNodeClientMaxRetries + 1, 1)
```

**File:** pinger/mirror_node_client.go (L59-61)
```go
		if !retry || attempt == attempts {
			break
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

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
```
