### Title
DNS Hijack via Unprotected HTTP Endpoint Causes Non-Retryable Empty Network Map, Preventing All Gossip

### Summary
`fetchMirrorNodeNetwork()` in `pinger/mirror_node_client.go` makes an unauthenticated, plain-HTTP request (the default Helm chart value is `http://{{ .Release.Name }}-restjava:80`) with no TLS certificate pinning. An attacker who poisons the DNS resolver used by the pinger pod can serve a response where every `node_account_id` is malformed, causing all nodes to be silently skipped at lines 107–110. The resulting empty `network` map triggers a `retry=false` error at line 128, which immediately breaks the retry loop at line 59 regardless of `mirrorNodeClientMaxRetries`, permanently preventing the pinger from building a network and submitting any transactions.

### Finding Description
**Exact code path:**

- `pinger/mirror_node_client.go`, `fetchMirrorNodeNetwork()`, lines 74–132
- HTTP client constructed at line 46 with no custom `Transport`, no TLS config, no certificate pinning: `httpClient := &http.Client{Timeout: cfg.mirrorNodeClientTimeout}`
- Default `mirrorRest` URL in `charts/hedera-mirror-pinger/values.yaml` line 19: `http://{{ .Release.Name }}-restjava:80` — plain HTTP, no TLS
- Lines 107–110: `hiero.AccountIDFromString()` failure silently `continue`s with no log, no counter
- Lines 127–129: empty `network` returns `nil, false, error` — the `false` (retry=false) is the critical flaw
- Lines 58–61 in `buildNetworkFromMirrorNodes`: `if !retry || attempt == attempts { break }` — `retry=false` causes immediate break after the very first attempt, nullifying all configured retries

**Root cause:** The code assumes the mirror REST endpoint is trustworthy and that any parse failure is a transient/benign event. It treats a fully-empty network as a non-retryable terminal error, and it makes no distinction between "server returned garbage" and "server is legitimately down."

**Exploit flow:**
1. Attacker poisons the DNS resolver used by the pinger (CoreDNS in-cluster, or upstream resolver if the URL is external)
2. Pinger resolves the mirror REST hostname to attacker-controlled IP
3. Attacker's server returns HTTP 200 with valid JSON structure but all `node_account_id` fields set to malformed strings (e.g., `"not.valid"`, `"x"`, `""` bypassed by line 103–105 check, or `"0.0.abc"`)
4. Every node entry hits `continue` at line 109
5. `network` map remains empty
6. Line 128 returns `retry=false` error
7. Line 59 breaks immediately — all configured retries are skipped
8. `buildNetworkFromMirrorNodes` returns `nil, error`
9. `newClient` in `sdk_client.go` fails → `main.go` line 43 calls `log.Fatalf` → pinger process exits

### Impact Explanation
The pinger is the component responsible for submitting gossip transactions to consensus nodes. If `buildNetworkFromMirrorNodes` fails at startup, the pinger exits immediately and never submits any transactions. This is a complete, persistent denial-of-service against the gossip/transaction submission path. The impact is not degraded performance — it is total cessation of pinger activity. Because the error is non-retryable (`retry=false`), even a single poisoned response during startup is sufficient; the attacker does not need to sustain the attack.

### Likelihood Explanation
The default deployment uses a plain HTTP URL (`http://...restjava:80`). Within a Kubernetes cluster, DNS poisoning of CoreDNS is achievable by any workload with sufficient RBAC permissions to modify ConfigMaps or by exploiting a co-located compromised pod. For deployments that expose `mirrorRest` as an external HTTP URL, DNS cache poisoning (Kaminsky-style) requires no privileged access to the target system — only the ability to send forged UDP DNS responses to the resolver. The attack is repeatable: every time the pinger restarts (e.g., after a crash loop or rolling update), the attacker can serve the poisoned response again.

### Recommendation
1. **Enforce HTTPS with certificate validation** for the mirror REST URL; reject `http://` schemes at config load time in `loadConfig()`.
2. **Change the empty-network error to retryable**: at line 128, return `nil, true, fmt.Errorf(...)` so the retry loop in `buildNetworkFromMirrorNodes` is actually exercised.
3. **Log a warning** when `AccountIDFromString` fails (lines 107–110) so operators can detect poisoned responses.
4. **Add response integrity checks**: validate that the returned node list is non-empty and that at least a minimum number of entries parse successfully before accepting the response.
5. Consider pinning the expected shard/realm prefix (e.g., `0.0.*`) and rejecting responses where all entries deviate from it.

### Proof of Concept
```
# 1. Stand up a fake HTTP server returning all-malformed node_account_ids:
cat > fake_mirror.json <<'EOF'
{"nodes":[
  {"node_account_id":"INVALID","service_endpoints":[{"ip_address_v4":"1.2.3.4","port":50211}]},
  {"node_account_id":"0.0.abc","service_endpoints":[{"ip_address_v4":"1.2.3.5","port":50211}]},
  {"node_account_id":"x.y.z","service_endpoints":[{"ip_address_v4":"1.2.3.6","port":50211}]}
],"links":{"next":null}}
EOF
python3 -m http.server 5551  # serve fake_mirror.json at /api/v1/network/nodes

# 2. Poison DNS so the pinger's mirrorRest hostname resolves to 127.0.0.1
#    (in-cluster: patch CoreDNS ConfigMap; externally: DNS cache poisoning)

# 3. Start the pinger with HIERO_MIRROR_PINGER_NETWORK=other
#    HIERO_MIRROR_PINGER_REST=http://<poisoned-hostname>:5551

# 4. Observe: pinger logs "attempt 1/11: no usable service_endpoints found from ..."
#    then immediately exits via log.Fatalf — no retries attempted, no transactions submitted.
```