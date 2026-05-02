### Title
Global-Only Gas Bucket Exhaustion via Distributed Source IPs (No Per-IP Throttling)

### Summary
`ThrottleManagerImpl.throttle()` enforces only a single JVM-local `gasLimitBucket` and `rateLimitBucket` shared across all callers with no per-source-IP accounting. An unprivileged attacker controlling multiple IPs (botnet, cloud VMs) can collectively exhaust the global gas bucket while each individual IP contributes only a fraction of the total, making IP-based blocking impossible at the application layer. Legitimate users receive `ThrottleException("Gas per second rate limit exceeded.")` for the duration of the attack.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.throttle()` (lines 37–49) performs two checks against singleton global buckets:

```java
if (!rateLimitBucket.tryConsume(1)) {                                      // global 500 req/s
    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
} else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {  // global 7.5B gas/s
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

The `gasLimitBucket` is a single `SynchronizationStrategy.SYNCHRONIZED` bean (`ThrottleConfiguration.java` lines 34–45) — one per JVM pod, shared by every caller regardless of origin.

**No per-IP field exists anywhere in the filter chain.** `RequestFilter.FilterField` (lines 39–48 of `RequestFilter.java`) enumerates only: `BLOCK`, `DATA`, `ESTIMATE`, `FROM`, `GAS`, `TO`, `VALUE`. The `FROM` field is the Ethereum sender address from the JSON body — not the HTTP source IP. `ContractCallRequest` (lines 20–57) contains no remote-address field. There is no mechanism to configure a per-IP bucket.

**Root cause / failed assumption:** The design assumes the global bucket is sufficient to protect the service. It fails to account for a distributed attacker who can collectively saturate the global budget while no single IP exceeds a detectable threshold.

**Why existing checks fail:**

1. The `RequestFilter` system has no `SOURCE_IP` / `REMOTE_ADDR` field — IP-based `REJECT` or `THROTTLE` rules cannot be configured.
2. The web3 Helm chart middleware (`charts/hedera-mirror-web3/values.yaml` lines 157–160) contains only a `retry` rule — **no per-IP `rateLimit` or `inFlightReq` with `sourceCriterion`** (contrast with the rosetta chart at lines 149–166 which has both).
3. The GCP gateway `maxRatePerEndpoint: 250` (line 56) is a per-backend-pod throughput cap, not a per-client-IP limit.
4. `sessionAffinity: type: CLIENT_IP` (line 57–58) is load-balancer stickiness, not a rate-limiting control.

### Impact Explanation

Default configuration: `gasPerSecond = 7_500_000_000`, `maxGasLimit = 15_000_000`, `requestsPerSecond = 500`. An attacker needs only 500 max-gas requests per second across all IPs to exhaust the gas bucket on one pod. With N pods, N×500 requests/s suffice. Once exhausted, every subsequent request — including legitimate ones — throws `ThrottleException` until the bucket refills (1-second window). This constitutes a sustained denial-of-service against the `/api/v1/contracts/call` endpoint, degrading or eliminating EVM simulation availability across targeted pods.

### Likelihood Explanation

Preconditions: zero — no authentication, no account, no privileged access required. The endpoint is public. Cloud spot instances or free-tier VMs across multiple providers provide hundreds of distinct IPs at negligible cost. Each IP sends requests at a rate well below any hypothetical per-IP threshold. The attack is repeatable every second indefinitely. The attacker does not need to know internal topology; exhausting the bucket on any reachable pod is sufficient to degrade that pod's availability.

### Recommendation

1. **Add `SOURCE_IP` to `RequestFilter.FilterField`** — inject `HttpServletRequest` into the throttle path and expose the remote address as a filterable field, enabling operators to configure per-IP `THROTTLE` or `REJECT` rules.
2. **Add per-IP rate limiting to the web3 Traefik/GCP middleware** — mirror the rosetta chart's `inFlightReq` with `sourceCriterion.ipStrategy` and `rateLimit` with `sourceCriterion.requestHost` in `charts/hedera-mirror-web3/values.yaml`.
3. **Use a distributed rate-limiting backend** (e.g., bucket4j with Redis) so per-IP limits are enforced consistently across all pods rather than per-JVM.
4. **Enforce a per-IP gas budget** in addition to the global budget so a single attacker cannot consume the entire global allowance regardless of how many IPs they use.

### Proof of Concept

```bash
# Attacker controls 50 cloud IPs; each sends 10 req/s at max gas (15M)
# Collectively: 50 * 10 = 500 req/s * 15_000_000 gas = 7.5B gas/s → bucket exhausted

# From each attacker IP (run in parallel across 50 hosts):
while true; do
  for i in $(seq 1 10); do
    curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
      -H 'Content-Type: application/json' \
      -d '{"data":"0x","to":"0x0000000000000000000000000000000000000001","gas":15000000}' &
  done
  sleep 1
done

# Legitimate user on a different IP observes:
curl -X POST https://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"data":"0x","to":"0x0000000000000000000000000000000000000001","gas":21000}'
# Response: 429 {"_status":{"messages":[{"message":"Gas per second rate limit exceeded."}]}}
```