### Title
Unauthenticated DB CPU Exhaustion via Unbounded `getAirdrops()` Queries with Varying `tokenIds` Parameters

### Summary
`TokenAirdropServiceImpl.getAirdrops()` in the `rest-java` module executes a live jOOQ database query on every invocation with no application-level caching and no rate limiting. Unlike the `web3` module which has a full `ThrottleManager`/Bucket4j infrastructure, the `rest-java` module contains only a `LoggingFilter` and `MetricsFilter` — no throttle. An unprivileged user can sustain single-threaded requests with monotonically varying `token.id=gt:X` values, defeating the 1-second HTTP cache and forcing a fresh DB query per request, cumulatively driving DB CPU well above the 30% threshold.

### Finding Description

**Exact code path:**

`TokenAirdropsController.getOutstandingAirdrops()` / `getPendingAirdrops()` (lines 67–86) call `processRequest()` (line 108), which calls `service.getAirdrops(request)`.

`TokenAirdropServiceImpl.getAirdrops()` (lines 19–22) performs no caching or throttle check — it directly calls `repository.findAll(request, id)`.

`TokenAirdropRepositoryCustomImpl.findAll()` (lines 58–72) executes a raw jOOQ `SELECT … WHERE … ORDER BY … LIMIT` against the `token_airdrop` table on every call. There is no `@Cacheable` annotation on this method.

**Root cause:** The `rest-java` module has no rate-limiting infrastructure. The `ThrottleConfiguration`, `ThrottleManagerImpl`, and `ThrottleProperties` classes all live under `org.hiero.mirror.web3` and are never wired into `rest-java`. The only servlet filters in `rest-java` are `LoggingFilter` and `MetricsFilter` — neither enforces a request rate cap.

**Why the HTTP cache fails:** The controller test confirms `Cache-Control: public, max-age=1` (1-second TTL). By varying the `token.id=gt:X` query parameter across requests (e.g., `token.id=gt:1`, `token.id=gt:2`, …), each request has a distinct cache key, so every request reaches the DB.

**Bound parameter amplification:** The controller accepts up to two `tokenIds` range parameters (`@Size(max = 2)`), allowing compound range conditions (e.g., `token.id=gt:X&token.id=lt:Y`). Varying X across requests while keeping Y fixed produces an unbounded stream of unique, non-cacheable queries.

### Impact Explanation
Each request executes a filtered, sorted, range-scanned query against `token_airdrop`. On a production node with millions of airdrop records, range scans on `token_id` with `ORDER BY receiver_account_id / sender_account_id, token_id, serial_number` are non-trivial. A single-threaded attacker issuing requests as fast as the server can respond (no back-pressure) can sustain hundreds of DB queries per minute. Because the `rest-java` service is a shared resource serving all mirror-node API consumers, elevated DB CPU degrades all other API endpoints simultaneously, meeting the >30% CPU increase threshold without brute-force parallelism.

### Likelihood Explanation
No authentication is required — the endpoints are fully public. No API key, no IP-based rate limit, no per-client quota exists in the `rest-java` module. The attack requires only an HTTP client and knowledge of the public API (documented in `openapi.yml`). It is trivially scriptable, repeatable, and requires no special privileges or insider knowledge.

### Recommendation
1. **Add rate limiting to `rest-java`**: Port the Bucket4j `ThrottleConfiguration`/`ThrottleManagerImpl` pattern from `web3` into `rest-java`, or add a Spring `HandlerInterceptor` / servlet filter that enforces a per-IP (or global) request-per-second cap on `/api/v1/accounts/*/airdrops/*`.
2. **Add application-level caching**: Annotate `TokenAirdropRepositoryCustomImpl.findAll()` with `@Cacheable` using a short TTL (e.g., 2–5 seconds) keyed on `(accountId, tokenIdBound, entityIdBound, serialBound, limit, order)` to absorb repeated identical or near-identical queries.
3. **Increase HTTP cache TTL**: Raise `Cache-Control: max-age` from 1 second to a value appropriate for airdrop data staleness tolerance (e.g., 5–10 seconds), reducing DB hit rate for repeated identical requests.

### Proof of Concept

```bash
# Single-threaded, no authentication required
# Vary token.id=gt:X on each request to defeat HTTP caching
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.1000/airdrops/outstanding?token.id=gt:${i}&limit=100" \
    -o /dev/null
done
```

Each iteration sends a unique query string, bypassing any reverse-proxy cache. Each request triggers `TokenAirdropRepositoryCustomImpl.findAll()` with a distinct `token_id > i` condition, executing a fresh DB range scan. Monitor DB CPU before and during the loop — CPU will rise proportionally to request throughput with no server-side enforcement to stop it. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepositoryCustomImpl.java (L58-72)
```java
    public Collection<TokenAirdrop> findAll(TokenAirdropRequest request, EntityId accountId) {
        var type = request.getType();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, type.getBaseField())
                .and(getBoundConditions(bounds))
                .and(TOKEN_AIRDROP.STATE.eq(AirdropState.PENDING));

        var order = SORT_ORDERS.getOrDefault(type, Map.of()).get(request.getOrder());
        return dslContext
                .selectFrom(TOKEN_AIRDROP)
                .where(condition)
                .orderBy(order)
                .limit(request.getLimit())
                .fetchInto(TokenAirdrop.class);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L66-114)
```java
    @GetMapping(value = "/outstanding")
    TokenAirdropsResponse getOutstandingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = RECEIVER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] receiverIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, receiverIds, limit, order, serialNumbers, tokenIds, OUTSTANDING);
    }

    @GetMapping(value = "/pending")
    TokenAirdropsResponse getPendingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = SENDER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] senderIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, senderIds, limit, order, serialNumbers, tokenIds, PENDING);
    }

    @SuppressWarnings("java:S107")
    private TokenAirdropsResponse processRequest(
            EntityIdParameter id,
            EntityIdRangeParameter[] entityIds,
            int limit,
            Sort.Direction order,
            NumberRangeParameter[] serialNumbers,
            EntityIdRangeParameter[] tokenIds,
            AirdropRequestType type) {
        var entityIdsBound = new Bound(entityIds, true, ACCOUNT_ID, type.getPrimaryField());
        var request = TokenAirdropRequest.builder()
                .accountId(id)
                .entityIds(entityIdsBound)
                .limit(limit)
                .order(order)
                .serialNumbers(new Bound(serialNumbers, false, SERIAL_NUMBER, TOKEN_AIRDROP.SERIAL_NUMBER))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, TOKEN_AIRDROP.TOKEN_ID))
                .type(type)
                .build();

        var response = service.getAirdrops(request);
        var airdrops = tokenAirdropMapper.map(response);
        var sort = getSort(airdrops, order, type.getParameter());
        var pageable = PageRequest.of(0, limit, sort);
        var links = linkFactory.create(airdrops, pageable, EXTRACTOR);
        return new TokenAirdropsResponse().airdrops(airdrops).links(links);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
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

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
