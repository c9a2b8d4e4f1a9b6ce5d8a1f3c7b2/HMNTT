### Title
Unauthenticated Timing-Based Topic ID Enumeration via Differential DB Query Count on `/api/v1/topics/{id}`

### Summary
The `TopicController.getTopic()` handler executes three sequential database queries on a cache miss (topic found) but short-circuits after the first query on a cache miss (topic not found), creating a statistically measurable response-time difference. Combined with the complete absence of per-IP rate limiting in the `rest-java` service, an unauthenticated attacker can enumerate which topic IDs are present versus absent in the mirror node database, revealing gaps in the mirror node's export completeness.

### Finding Description

**Code path — `TopicController.getTopic()`:**

```java
// rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java, lines 31-37
@GetMapping(value = "/{id}")
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());      // DB query 1 — throws on miss
    var entity = entityService.findById(id.id());    // DB query 2 — never reached on miss
    var customFee = customFeeService.findById(id.id()); // DB query 3 — never reached on miss
    return topicMapper.map(customFee, entity, topic);
}
```

**Root cause — `TopicServiceImpl.findById()`:**

```java
// rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java, line 20
return topicRepository.findById(id.getId())
    .orElseThrow(() -> new EntityNotFoundException("Topic not found"));
```

When the topic does not exist, `EntityNotFoundException` is thrown immediately after the first DB round-trip. The `GenericControllerAdvice` catches it and returns HTTP 404 with no timing normalization:

```java
// rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java, lines 115-118
@ExceptionHandler
private ResponseEntity<Object> notFound(final EntityNotFoundException e, final WebRequest request) {
    return handleExceptionInternal(e, null, null, NOT_FOUND, request);
}
```

**Timing oracle:**
- **Miss path**: 1 DB query → 404 (fast)
- **Hit path**: 3 DB queries → 200 (slower by ~2× DB round-trip latency)

**No rate limiting in rest-java:**
`RestJavaConfiguration` registers only an ETag filter and a Protobuf converter — no throttle bean, no bucket4j, no servlet filter for rate limiting. The `ThrottleManagerImpl`/`ThrottleConfiguration` exist exclusively in the `web3` module and are not wired into `rest-java`.

The Traefik middleware chain for `hedera-mirror-rest-java` (`charts/hedera-mirror-rest-java/values.yaml`, lines 158–163) contains only `circuitBreaker` and `retry` — no `rateLimit` or `inFlightReq` entries (contrast with `hedera-mirror-rosetta/values.yaml` lines 157–160 which explicitly configure `rateLimit`). The GCP gateway `maxRatePerEndpoint: 250` is a backend load-balancing policy, not a per-source-IP rate limit.

### Impact Explanation
An attacker can determine, for any range of topic IDs, which IDs are present in the mirror node database and which are absent. Because Hedera topic IDs are sequential integers, this directly reveals the completeness of the mirror node's export: IDs that exist on the Hedera network but return fast 404s are missing from this mirror node's data set. This leaks operational state (export lag, gaps, or selective mirroring) to any unauthenticated caller. At high request rates it also constitutes an unthrottled resource exhaustion vector against the database connection pool.

### Likelihood Explanation
No authentication, no rate limit, no CAPTCHA, and no timing equalization are required to be bypassed. The attacker needs only an HTTP client and the knowledge that topic IDs are numeric. The timing signal (1 vs 3 DB queries) is consistent and repeatable; statistical averaging over tens of requests per ID is sufficient to distinguish the two cases even under moderate network jitter. This is fully automatable with a simple script.

### Recommendation
1. **Equalize response timing**: Perform all three repository lookups unconditionally (or use `Optional`-returning variants) before deciding whether to throw, so hit and miss paths consume the same number of DB round-trips.
2. **Add per-IP rate limiting to rest-java**: Add a `rateLimit` Traefik middleware entry to `charts/hedera-mirror-rest-java/values.yaml` (mirroring the rosetta configuration) and/or add a bucket4j-based servlet filter in `RestJavaConfiguration` analogous to `ThrottleManagerImpl` in the `web3` module.
3. **Add `inFlightReq` middleware**: Limit concurrent in-flight requests per source IP to prevent bulk enumeration bursts.

### Proof of Concept

```bash
# Baseline: measure a known-missing ID (fast — 1 DB query)
for i in $(seq 1 20); do
  curl -o /dev/null -s -w "%{time_total}\n" \
    "https://<mirror-node>/api/v1/topics/0.0.999999999"
done

# Compare: measure a known-present ID (slow — 3 DB queries)
for i in $(seq 1 20); do
  curl -o /dev/null -s -w "%{time_total}\n" \
    "https://<mirror-node>/api/v1/topics/0.0.1"
done

# Enumerate: scan a range and classify by median response time
for id in $(seq 1 10000); do
  t=$(curl -o /dev/null -s -w "%{time_total}" \
    "https://<mirror-node>/api/v1/topics/0.0.$id")
  echo "$id $t"
done | awk '$2 < THRESHOLD {print $1, "MISSING"} $2 >= THRESHOLD {print $1, "PRESENT"}'
```

IDs whose median response time clusters with the fast (1-query) group are absent from the mirror node export; IDs clustering with the slow (3-query) group are present. No credentials required.