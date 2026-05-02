### Title
Unauthenticated GraphQL Account Query Flood Causes Readiness Probe Failure and Pod Eviction

### Summary
The GraphQL service exposes the `account(input: AccountInput!)` query with no application-level rate limiting. Each request triggers a synchronous database lookup. The Kubernetes readiness probe has a `timeoutSeconds: 2` timeout against `/actuator/health/readiness`. A distributed unauthenticated attacker can flood the service with `account(input: {entityId: {num: N}})` requests, exhaust the HikariCP database connection pool, delay the health endpoint response beyond 2 seconds, and cause Kubernetes to remove the pod from the load balancer, partitioning legitimate users from the service.

### Finding Description

**Exact code locations:**

`graphql/src/main/resources/graphql/query.graphqls` line 5 — the sole public query entry point, no authentication or rate-limit directive: [1](#0-0) 

`graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java` lines 33–44 — every call unconditionally issues a synchronous DB query via `entityRepository.findById()`: [2](#0-1) 

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java` line 25 — the DB call itself: [3](#0-2) 

`charts/hedera-mirror-graphql/values.yaml` lines 296–301 — readiness probe with `timeoutSeconds: 2`: [4](#0-3) 

**Root cause:** The `graphql` module contains zero application-level rate limiting. The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` rate-limiting stack exists exclusively in the `web3` module and is never wired into the GraphQL service: [5](#0-4) 

`GraphQlConfiguration` applies only query-complexity and query-depth instrumentation — no request-rate control: [6](#0-5) 

**Exploit flow:**

1. Attacker distributes requests across multiple source IPs (cloud VMs, proxies) to bypass the Traefik `inFlightReq: amount: 5` per-IP limit.
2. Each IP sends 5 concurrent `POST /graphql/alpha` requests with body `{"query":"{ account(input:{entityId:{num:1}}){id} }"}`.
3. Each request acquires a HikariCP connection and holds it for the duration of the DB round-trip.
4. With enough concurrent connections the pool is saturated; new requests queue or time out.
5. Spring Boot's `/actuator/health/readiness` endpoint itself performs a DB connectivity check (DataSourceHealthIndicator). Under pool exhaustion this check blocks beyond 2 seconds.
6. Kubernetes marks the pod `NotReady` and removes it from the Service endpoints.
7. All user traffic is partitioned away from that pod; if all replicas are affected, the service is fully unavailable.

**Why the Traefik retry middleware amplifies the attack:**

`charts/hedera-mirror-graphql/values.yaml` lines 135–145 — `retry.attempts: 3` causes Traefik to re-issue each timed-out request up to 3 additional times, multiplying backend load by up to 4×: [7](#0-6) 

### Impact Explanation

A successful attack removes one or more GraphQL pods from the Kubernetes load balancer. With `hpa.minReplicas: 1` and `podDisruptionBudget.enabled: false` (defaults), a single-pod deployment is fully unavailable. Even with multiple replicas, the attack scales linearly: each additional attacker IP contributes 5 more concurrent DB connections. The circuit breaker (`NetworkErrorRatio() > 0.10`) may open and block legitimate traffic before the readiness probe recovers, extending the outage window. [8](#0-7) 

### Likelihood Explanation

No authentication or API key is required to reach `/graphql/alpha`. The query is trivially small (under 50 bytes). Distributing across multiple IPs to bypass the per-IP `inFlightReq: 5` limit requires only commodity cloud instances or a small botnet — well within reach of any motivated attacker. The attack is repeatable: once the pod recovers and rejoins the load balancer, the flood can resume immediately.

### Recommendation

1. **Add application-level rate limiting to the GraphQL module.** Port the existing `ThrottleConfiguration` / `ThrottleManagerImpl` pattern from `web3` into `graphql`, or add a Spring `HandlerInterceptor` / WebFlux filter that enforces a per-IP request-per-second budget before the GraphQL execution pipeline is entered.
2. **Decouple the readiness probe from the DB connection pool.** Use a dedicated lightweight health indicator that does not acquire a HikariCP connection (e.g., check pool availability rather than issuing a query), or increase `timeoutSeconds` to a value that accommodates transient pool pressure without triggering pod eviction.
3. **Disable or reconfigure the Traefik retry middleware** for the GraphQL ingress. Retrying on 5xx/timeout responses under load amplifies the attack; retries should only apply to network-level errors, not application overload.
4. **Enable `podDisruptionBudget`** and set `minAvailable` to ensure at least one replica remains in service during an attack.

### Proof of Concept

```bash
# Distribute across N source IPs (replace IP_LIST with attacker-controlled IPs)
# Each IP sends 5 concurrent requests in a tight loop

for IP in $IP_LIST; do
  ssh $IP "while true; do
    for i in \$(seq 1 5); do
      curl -s -X POST https://<target>/graphql/alpha \
        -H 'Content-Type: application/json' \
        -d '{\"query\":\"{ account(input:{entityId:{num:1}}){id} }\"}' &
    done
    wait
  done" &
done

# Monitor pod readiness — expect NotReady within seconds of flood start
kubectl get endpoints <graphql-service> -w
```

Expected result: pod transitions to `NotReady`, endpoint is removed from the Service, and legitimate requests receive connection-refused or 503 errors from the load balancer.

### Citations

**File:** graphql/src/main/resources/graphql/query.graphqls (L4-6)
```text
type Query {
    account(input: AccountInput!): Account
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L32-45)
```java
    @QueryMapping
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L23-26)
```java
    @Override
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** charts/hedera-mirror-graphql/values.yaml (L93-104)
```yaml
hpa:
  behavior: {}
  enabled: false
  maxReplicas: 8
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80
  minReplicas: 1
```

**File:** charts/hedera-mirror-graphql/values.yaml (L135-146)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - retry:
      attempts: 3
      initialInterval: 100ms

```

**File:** charts/hedera-mirror-graphql/values.yaml (L296-301)
```yaml
readinessProbe:
  httpGet:
    path: /actuator/health/readiness
    port: http
  initialDelaySeconds: 40
  timeoutSeconds: 2
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L41-49)
```java
    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
    }
```
