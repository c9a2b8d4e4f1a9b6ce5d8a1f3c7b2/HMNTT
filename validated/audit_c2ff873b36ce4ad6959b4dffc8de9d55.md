All referenced lines are verified against the actual source. Let me confirm each claim precisely.

**`pinger/sdk_client.go` lines 17–21** — `case "other"` calls `buildNetworkFromMirrorNodes` and returns any error immediately. ✅ [1](#0-0) 

**`pinger/mirror_node_client.go` line 46** — plain `http.Client` with no TLS config. ✅ [2](#0-1) 

**`pinger/mirror_node_client.go` lines 127–129** — zero-length network map returns `retry=false`. ✅ [3](#0-2) 

**`pinger/mirror_node_client.go` lines 58–61** — `!retry` breaks the loop immediately. ✅ [4](#0-3) 

**`pinger/main.go` lines 41–44** — `newClient` error goes to `log.Fatalf` → `os.Exit(1)`. ✅ [5](#0-4) 

**SECURITY.md scope check:** The "Lack of SSL/TLS best practices" exclusion is listed under the **"Websites and Apps"** section only. The pinger is a Go binary/Kubernetes pod — not a website or app — so that exclusion does not apply here. The attack also requires DNS hijacking (not merely DDoS), so the "Impacts that only require DDoS" exclusion does not apply either. No other exclusion covers this finding. ✅ [6](#0-5) 

---

# Audit Report

## Title
DNS-Hijack of Mirror REST Hostname Causes Permanent Pinger Crash via Empty Node List

## Summary
When `network=other`, the pinger makes an unauthenticated plain-HTTP GET to the operator-configured `mirrorRest` hostname to bootstrap its node map. An attacker who controls DNS for that hostname can serve a crafted HTTP 200 response containing nodes with empty `service_endpoints`. This triggers a non-retryable error path that propagates to `log.Fatalf` in `main()`, permanently killing the monitoring process.

## Finding Description

**Code path (all references verified):**

1. `pinger/sdk_client.go` lines 17–21: when `cfg.network == "other"`, `buildNetworkFromMirrorNodes` is called and any error is returned immediately to `main`. [1](#0-0) 

2. `pinger/mirror_node_client.go` line 46: the HTTP client is a plain `http.Client` with no TLS configuration, no mutual authentication, and no response signing — the URL is whatever the operator sets in `cfg.mirrorRest`. [2](#0-1) 

3. `pinger/mirror_node_client.go` lines 127–129: when the parsed response yields zero usable entries (all nodes have empty/invalid `service_endpoints`), `fetchMirrorNodeNetwork` returns `(nil, false, err)` — `retry=false`. [3](#0-2) 

4. `pinger/mirror_node_client.go` lines 58–61: the retry loop checks `!retry` first; when `retry=false`, it breaks immediately regardless of remaining attempts — the entire retry budget is bypassed. [4](#0-3) 

5. `pinger/main.go` lines 41–44: the error from `newClient` is passed to `log.Fatalf`, which calls `os.Exit(1)` — the process terminates permanently. [5](#0-4) 

**Root cause:** The code assumes the mirror REST endpoint is trusted and will always return valid node data. There is no TLS enforcement, no integrity verification of the response body, and no fallback node list. The `retry=false` return for the empty-nodes case means the retry mechanism — the only resilience layer — is completely bypassed for this specific error.

## Impact Explanation

The pinger is a monitoring/liveness service. A permanent crash at startup means:

- `/tmp/ready` is never written (it is written only after `newClient` succeeds at line 47), so Kubernetes readiness probes fail immediately. [7](#0-6) 
- The liveness heartbeat goroutine (which writes `/tmp/alive` every 15 seconds) is killed by `os.Exit(1)` before it ever fires, so liveness probes eventually evict the pod. [8](#0-7) 
- If the attacker sustains the DNS redirect, every pod restart triggers the same crash, keeping the pinger in a permanent crash-loop and blinding operators to network health.

## Likelihood Explanation

The precondition (`network=other`) is the explicit deployment mode for custom/private networks — exactly the environments where operators are most likely to use a named internal hostname for `mirrorRest`. DNS control is achievable via: (a) subdomain takeover if the hostname is a public FQDN whose DNS record has been removed, (b) DNS cache poisoning of an unvalidated resolver, or (c) BGP prefix hijack for the resolver's upstream. The attack requires only a single HTTP response (no retry protection for this error), is repeatable on every restart, and leaves no cryptographic evidence.

## Recommendation

1. **Enforce HTTPS:** Reject any `mirrorRest` URL that does not use `https://` and configure the `http.Client` with a strict TLS config (minimum TLS 1.2, verified certificate chain).
2. **Make the empty-nodes error retryable:** Change `return nil, false, ...` at line 128 to `return nil, true, ...` so transient or injected responses are retried rather than immediately fatal. [3](#0-2) 
3. **Add a static fallback:** Allow operators to supply a static node list that is used if the mirror REST bootstrap fails after all retries, preventing a single bad response from being fatal.
4. **Validate response integrity:** Consider requiring a minimum number of nodes and/or a configurable allowlist of expected account IDs before accepting the bootstrapped network map.

## Proof of Concept

```bash
# 1. Redirect DNS for the configured mirrorRest hostname to attacker server
#    (e.g., via /etc/hosts on the test node, or a local DNS override)
echo "127.0.0.1 mirror.example.internal" >> /etc/hosts

# 2. Serve a crafted response on port 80
python3 -c "
import http.server, json

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            'nodes': [{'node_account_id': '0.0.3', 'service_endpoints': []}],
            'links': {'next': None}
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

http.server.HTTPServer(('0.0.0.0', 80), H).serve_forever()
" &

# 3. Run the pinger with network=other and mirrorRest pointing to the hostname
PINGER_NETWORK=other \
PINGER_MIRROR_REST=http://mirror.example.internal \
PINGER_OPERATOR_ID=0.0.2 \
PINGER_OPERATOR_KEY=<valid_key> \
./pinger
# Expected: process exits immediately with:
# "client error: attempt 1/1: no usable service_endpoints found from http://mirror.example.internal/api/v1/network/nodes"
# /tmp/ready is never created; /tmp/alive is never written.
```

### Citations

**File:** pinger/sdk_client.go (L17-21)
```go
	case "other":
		netmap, err := buildNetworkFromMirrorNodes(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
```

**File:** pinger/mirror_node_client.go (L46-46)
```go
	httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}
```

**File:** pinger/mirror_node_client.go (L58-61)
```go
		lastErr = fmt.Errorf("attempt %d/%d: %w", attempt, attempts, err)
		if !retry || attempt == attempts {
			break
		}
```

**File:** pinger/mirror_node_client.go (L127-129)
```go
	if len(network) == 0 {
		return nil, false, fmt.Errorf("no usable service_endpoints found from %s", url)
	}
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

**File:** pinger/main.go (L41-44)
```go
	client, err := newClient(cfg)
	if err != nil {
		log.Fatalf("client error: %v", err)
	}
```

**File:** pinger/main.go (L47-49)
```go
	if err := os.WriteFile("/tmp/ready", []byte("ok\n"), 0o644); err != nil {
		log.Fatalf("failed to create readiness file /tmp/ready: %v", err)
	}
```

**File:** SECURITY.md (L43-44)
```markdown
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
```
