I need to verify all the specific claims before rendering a verdict. Let me check the remaining reference.

All five factual claims have been verified against the actual codebase. Here is the verdict:

---

Audit Report

## Title
Missing Back-Pressure and Rate-Limiting in `TopicServiceImpl.findById()` Enables Retry-Amplified Thread Exhaustion During DB Partition

## Summary
The `rest-java` Traefik ingress middleware chain is missing `inFlightReq` and `rateLimit` controls that are present in comparable services. Combined with a blocking synchronous JPA call in `TopicServiceImpl.findById()` and a `retry` middleware that runs before the circuit breaker observes errors, an unauthenticated attacker can exhaust the JVM thread pool during any DB connectivity degradation, extending the effective outage window.

## Finding Description

**`TopicServiceImpl.findById()` — blocking JPA call, no concurrency guard:**

`TopicServiceImpl.findById()` at line 20 issues a synchronous, blocking call to `topicRepository.findById()` backed by HikariCP: [1](#0-0) 

This is invoked directly from `TopicController.getTopic()` at line 33 with no concurrency limit or semaphore: [2](#0-1) 

**`rest-java` Traefik middleware — only `circuitBreaker` + `retry`:**

The `rest-java` Helm chart configures only two middlewares: [3](#0-2) 

**`hedera-mirror-rosetta` middleware — includes `inFlightReq` and `rateLimit`:**

The rosetta chart additionally configures per-IP in-flight capping (max 5) and per-host rate limiting (10 req/s): [4](#0-3) 

**No application-level throttling in `rest-java`:**

`web3` has a bucket4j-based `ThrottleManagerImpl` that enforces request-per-second and gas-per-second limits: [5](#0-4) 

No equivalent exists anywhere under `rest-java/`.

**Middleware ordering and retry amplification:**

In Traefik, middleware is applied in declaration order. With `circuitBreaker` listed first and `retry` second, the circuit breaker is the *outer* wrapper: it observes only the final outcome after all retry attempts have been exhausted. Each original request that fails causes 3 backend attempts before the circuit breaker records a single error. This means the circuit breaker accumulates errors at 1/3 the actual backend failure rate, delaying its opening by up to 3×.

## Impact Explanation
During any DB network partition, each `findById()` call blocks a servlet thread for the duration of HikariCP's connection acquisition timeout (default 30 s). With no `inFlightReq` cap, unbounded concurrent requests pile up blocked threads. The retry middleware triples the number of in-flight DB connection attempts per original request. Thread pool and HikariCP pool exhaustion prevents health-check and DB reconnection probes from acquiring threads, extending the outage beyond the actual partition window. No authentication is required.

## Likelihood Explanation
The attack surface is a public, unauthenticated `GET /api/v1/topics/{id}` endpoint. No credentials, tokens, or special knowledge are required — a simple `ab` or `curl` loop suffices. DB partitions are common in cloud environments. The configuration gap (missing `inFlightReq`/`rateLimit` in `rest-java` vs. `rosetta`) is exploitable opportunistically on any transient DB instability.

## Recommendation
Add `inFlightReq` and `rateLimit` entries to the `middleware` list in `charts/hedera-mirror-rest-java/values.yaml`, mirroring the rosetta configuration:

```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 100          # tune to thread-pool size
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 50          # tune to expected traffic
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
```

Additionally, consider adding an application-level concurrency guard (e.g., a `Semaphore` or Resilience4j `Bulkhead`) in `TopicServiceImpl` or `TopicController`, and reducing HikariCP's `connectionTimeout` to fail fast rather than holding threads for 30 s.

## Proof of Concept
```bash
# Simulate DB partition (e.g., via network policy or iptables on the DB node), then:
ab -n 100000 -c 500 https://<host>/api/v1/topics/0.0.1234
# Each of the 500 concurrent requests blocks a thread for ~30s (HikariCP timeout).
# Traefik retries each 3×, tripling backend load.
# After ~thread-pool-size / 500 seconds, all threads are exhausted.
# Health checks at /actuator/health/liveness stop responding → pod marked unhealthy.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L31-37)
```java
    @GetMapping(value = "/{id}")
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L158-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L20-49)
```java
final class ThrottleManagerImpl implements ThrottleManager {

    static final String REQUEST_PER_SECOND_LIMIT_EXCEEDED = "Requests per second rate limit exceeded";
    static final String GAS_PER_SECOND_LIMIT_EXCEEDED = "Gas per second rate limit exceeded.";

    @Qualifier(GAS_LIMIT_BUCKET)
    private final Bucket gasLimitBucket;

    @Qualifier(RATE_LIMIT_BUCKET)
    private final Bucket rateLimitBucket;

    @Qualifier(OPCODE_RATE_LIMIT_BUCKET)
    private final Bucket opcodeRateLimitBucket;

    private final ThrottleProperties throttleProperties;

    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
