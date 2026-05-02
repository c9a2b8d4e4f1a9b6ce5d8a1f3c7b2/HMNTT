### Title
X-Forwarded-For Spoofing Bypasses Traefik `inFlightReq` Per-IP Concurrency Limit on `account()` GraphQL Query

### Summary
Traefik is globally configured with `--entryPoints.web.forwardedHeaders.insecure` and `--entryPoints.websecure.forwardedHeaders.insecure`, which causes it to unconditionally trust all `X-Forwarded-For` headers from any source. The `inFlightReq` middleware protecting the GraphQL endpoint uses `ipStrategy.depth: 1`, which derives the source IP from that untrusted header. An unauthenticated external attacker can rotate arbitrary spoofed IPs in the `X-Forwarded-For` header to present a fresh identity to the limiter on every request, completely bypassing the 5-concurrent-request cap and flooding the backend with unlimited parallel `account()` queries.

### Finding Description
**Code locations:**

`charts/hedera-mirror-common/values.yaml`, lines 635–637 — Traefik is started with:
```yaml
globalArguments:
  - --entryPoints.web.forwardedHeaders.insecure
  - --entryPoints.websecure.forwardedHeaders.insecure
``` [1](#0-0) 

This flag instructs Traefik to accept and trust `X-Forwarded-For` headers from **any** connecting client with no IP allowlist, no signature, and no depth-based stripping of client-supplied values.

`charts/hedera-mirror-graphql/values.yaml`, lines 138–142 — The `inFlightReq` middleware is:
```yaml
- inFlightReq:
    amount: 5
    sourceCriterion:
      ipStrategy:
        depth: 1
``` [2](#0-1) 

`depth: 1` tells Traefik to use the **rightmost** IP in the `X-Forwarded-For` header as the source identity for the in-flight counter. Because `forwardedHeaders.insecure` is set, that rightmost IP is whatever the client wrote — it is never validated or stripped.

`graphql/src/main/resources/graphql/query.graphqls`, line 5 — the targeted operation:
```graphql
account(input: AccountInput!): Account
``` [3](#0-2) 

**Exploit flow:**

1. Attacker sends HTTP POST to `/graphql/alpha` with a slow or blocking `account()` query.
2. Each request carries a unique, attacker-chosen `X-Forwarded-For` value (e.g., `X-Forwarded-For: 10.0.0.1`, then `10.0.0.2`, etc.).
3. Traefik reads the rightmost XFF IP as the source (depth=1) and looks up that IP's in-flight counter.
4. Because each spoofed IP has counter = 0, every request is admitted — the `amount: 5` limit is never reached for any single identity.
5. The attacker accumulates an unbounded number of concurrent requests against the GraphQL backend.

**Why existing checks fail:**

- The `circuitBreaker` middleware fires only after errors or latency have already accumulated — it does not prevent the initial flood.
- The `retry` middleware is irrelevant to concurrency limiting.
- There is no authentication or API key requirement on the GraphQL endpoint.
- There is no secondary rate-limit (token bucket / rate-per-second) that would catch high-volume spoofed traffic.
- The `inFlightReq` middleware is the sole concurrency guard, and it is entirely defeated by the spoofed header.

### Impact Explanation
An unprivileged external attacker can saturate the GraphQL service with arbitrarily many concurrent `account()` queries. Each query triggers database lookups. The result is resource exhaustion (CPU, DB connections, memory) on the GraphQL pods and the backing PostgreSQL/PgBouncer pool, causing denial of service for all legitimate users. The `GraphQLHighDBConnections` and `GraphQLHighCPU` Prometheus alerts would fire, but only after the damage is already occurring. [4](#0-3) 

### Likelihood Explanation
No privileges, accounts, or special network position are required. The attack requires only the ability to send HTTP requests to the public GraphQL endpoint (enabled by default via the Traefik ingress) and the ability to set arbitrary HTTP headers, which every HTTP client supports. The spoofed IPs do not need to be routable — Traefik never validates them. The attack is trivially scriptable and fully repeatable.

### Recommendation
1. **Remove `forwardedHeaders.insecure`** from both entry points. Instead, configure `forwardedHeaders.trustedIPs` to list only the known upstream load balancer or CDN CIDR ranges. This ensures Traefik only trusts XFF values appended by infrastructure it controls.
2. **Add `excludedIPs`** or use `depth: 0` (remote address) for the `inFlightReq` `ipStrategy` if a trusted proxy chain cannot be guaranteed, so the limiter always keys on the actual TCP peer address.
3. Consider adding a **rate-per-second** (`rateLimit`) middleware in addition to `inFlightReq` to limit request throughput per IP independently of concurrency. [5](#0-4) 

### Proof of Concept
```bash
# Send 50 concurrent slow account() queries, each with a unique spoofed source IP.
# Replace <HOST> with the public GraphQL endpoint.

for i in $(seq 1 50); do
  curl -s -X POST https://<HOST>/graphql/alpha \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.${i}" \
    -d '{"query":"{ account(input:{entityId:{shard:0,realm:0,num:2}}) { balance { balance } } }"}' &
done
wait
```

Each request presents a distinct IP to the `inFlightReq` counter (`10.0.0.1` through `10.0.0.50`). All 50 are admitted simultaneously. Repeating with a larger range (or randomized IPs) produces an unbounded concurrent load on the backend, confirming the bypass.

### Citations

**File:** charts/hedera-mirror-common/values.yaml (L622-638)
```yaml
traefik:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 100
          podAffinityTerm:
            topologyKey: kubernetes.io/hostname
            labelSelector:
              matchLabels:
                app.kubernetes.io/name: traefik
  deployment:
    kind: DaemonSet
  enabled: true
  globalArguments:  # Expose X-Forwarded-For header for tracing
    - --entryPoints.web.forwardedHeaders.insecure
    - --entryPoints.websecure.forwardedHeaders.insecure
    - --api.insecure=true
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-142)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
```

**File:** charts/hedera-mirror-graphql/values.yaml (L204-214)
```yaml
  GraphQLHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror GraphQL API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="graphql"}) by (namespace, pod) / sum(hikaricp_connections_max{application="graphql"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: graphql
      area: resource
      severity: critical
```

**File:** graphql/src/main/resources/graphql/query.graphqls (L5-5)
```text
    account(input: AccountInput!): Account
```
