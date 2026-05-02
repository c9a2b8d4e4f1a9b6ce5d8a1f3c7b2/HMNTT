### Title
Unauthenticated Topic ID Enumeration via Absent Rate Limiting on GET /api/v1/topics/{id}

### Summary
The `getTopic()` handler in `TopicController.java` accepts any numeric entity ID with no authentication, no rate limiting, and no per-IP throttling. Each request triggers three synchronous database queries against the mirror node's PostgreSQL backend. An unprivileged attacker can sequentially scan the full valid ID space to enumerate all existing HCS topics and exhaust database connection pools.

### Finding Description

**Exact code path:**

`rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 31–37:

```java
@GetMapping(value = "/{id}")
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());       // DB query 1
    var entity = entityService.findById(id.id());     // DB query 2
    var customFee = customFeeService.findById(id.id()); // DB query 3
    return topicMapper.map(customFee, entity, topic);
}
```

Each call unconditionally fires three independent repository lookups (`TopicRepository`, `EntityRepository`, `CustomFeeRepository`) with no caching layer.

**Root cause — no rate limiting at any layer:**

*Application layer:* The `rest-java` config package contains only `LoggingFilter`, `MetricsFilter`, `RestJavaConfiguration` (ETag + protobuf), and `WebMvcConfiguration`. There is no `ThrottleConfiguration`, no bucket4j bean, and no `@RateLimiter` annotation anywhere in the `rest-java` module. Compare with the `web3` module, which has a full `ThrottleConfiguration` + `ThrottleManagerImpl` using bucket4j.

*Infrastructure layer:* `charts/hedera-mirror-rest-java/values.yaml` lines 158–163 define the Traefik middleware chain for rest-java as only:
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ...
  - retry:
      attempts: 3
      initialInterval: 100ms
```
There is no `rateLimit` or `inFlightReq` entry — unlike the rosetta chart which explicitly configures both. Furthermore, the middleware template (`charts/hedera-mirror-rest-java/templates/middleware.yaml` line 3) only renders when `global.middleware` is `true`, but `global.middleware` defaults to `false` (line 103 of values.yaml), meaning even the circuit breaker is disabled by default.

*ID space:* `EntityIdNumParameter.java` line 12 accepts `\d{1,12}`, covering 0–999999999999. The EntityId NUM_MASK caps the meaningful range at 274,877,906,943 — still a trivially iterable space for a distributed scanner.

**Why existing checks fail:**

- The circuit breaker triggers only on aggregate error ratios, not on per-IP request volume.
- The retry middleware amplifies, not limits, requests.
- `TopicServiceImpl.findById()` throws `EntityNotFoundException` (404) for non-existent IDs — a distinguishable signal that costs the same three DB queries as a hit.
- No authentication or API key is required.

### Impact Explanation

An attacker obtains a complete map of all HCS topics registered on the network: topic IDs, admin/submit keys, custom fee schedules, memo fields, and lifecycle timestamps. This reconnaissance directly identifies high-value topics (e.g., those used for application-layer gossip, oracle feeds, or governance). Beyond enumeration, sustained scanning at scale exhausts the HikariCP connection pool (alerted only after the fact via `RestJavaHighDBConnections` Prometheus rule), degrading availability for legitimate users. The mirror node's own alerting (`RestJavaNoRequests`, `RestJavaQueryLatency`) is reactive, not preventive.

### Likelihood Explanation

No privileges, accounts, or credentials are required. The endpoint is publicly routable via the ingress path `/api/v1/topics/(\d+\.){0,2}\d+$`. A single machine issuing ~1,000 req/s can scan the practical topic space (topics are sparse; most IDs return 404 quickly) within hours. Distributed scanning from multiple IPs faces no per-IP control whatsoever. This is a standard reconnaissance technique requiring only `curl` or any HTTP client in a loop.

### Recommendation

1. **Application-layer rate limiting:** Add a bucket4j `ThrottleConfiguration` bean to `rest-java` mirroring the pattern in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, and apply it in a servlet filter on `/api/v1/topics/**`.
2. **Traefik middleware:** Add `inFlightReq` and `rateLimit` entries to `charts/hedera-mirror-rest-java/values.yaml` middleware list (matching the rosetta chart pattern), and set `global.middleware: true` in production overlays.
3. **Response caching:** Cache 404 responses for non-existent IDs to avoid three DB queries per miss.
4. **Monitoring:** Add a Prometheus alert on per-IP request rate, not just aggregate error ratios.

### Proof of Concept

```bash
# Enumerate existing topics sequentially (no credentials needed)
for id in $(seq 1 1000000); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://<mirror-node>/api/v1/topics/$id")
  if [ "$status" = "200" ]; then
    echo "EXISTS: topic $id"
    curl -s "https://<mirror-node>/api/v1/topics/$id" | jq .
  fi
done

# Parallel scan (distributed, no rate limit encountered)
seq 1 274877906943 | xargs -P 500 -I{} \
  curl -s -o /dev/null -w "%{http_code} {}\n" \
  "https://<mirror-node>/api/v1/topics/{}" | grep "^200"
```

Each 200 response reveals the topic's admin key, submit key, custom fee schedule, and memo — sufficient to identify and subsequently target high-value HCS topics on the live Hedera network.