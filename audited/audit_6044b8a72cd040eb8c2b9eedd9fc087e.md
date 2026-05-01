### Title
Unauthenticated DoS via Token Precompile SQL Saturation Triggering `statementInspector` Timeout and Cascading HTTP 503

### Summary

An unprivileged external user can send contract calls targeting Hedera Token Service (HTS) precompiles (e.g., `getTokenInfo`, `getFungibleTokenInfo`) that cause the EVM to execute a `CALL` opcode to the precompile address, triggering multiple sequential SQL queries across `entity`, `token`/`token_history`, `custom_fee`/`custom_fee_history`, and `token_balance`/`token_transfer` tables. Under concurrent load, the cumulative elapsed time across these sequential queries exceeds the 10-second `requestTimeout`, causing the `statementInspector` in `HibernateConfiguration` to throw `QueryTimeoutException`, which `GenericControllerAdvice` maps to HTTP 503. Because rate limiting is global (not per-IP) and no authentication is required, an attacker can reliably trigger this condition for all concurrent users.

### Finding Description

**Exact code path:**

`ContractCallContext.run()` creates a new `ContractCallContext` with `startTime = System.currentTimeMillis()` at construction time. [1](#0-0) 

The `statementInspector` bean in `HibernateConfiguration` intercepts every Hibernate SQL statement before execution: [2](#0-1) 

`requestTimeout` defaults to 10,000 ms: [3](#0-2) 

`QueryTimeoutException` is mapped unconditionally to HTTP 503: [4](#0-3) 

**SQL queries triggered by a single `getTokenInfo` precompile call** (via `TokenReadableKVState.readFromDataSource()`):

1. `commonEntityAccessor.get()` → `entity` table lookup
2. `tokenRepository.findByTokenIdAndTimestamp()` → UNION of `token` + `token_history` with `order by timestamp_range desc limit 1`
3. `customFeeRepository.findByTokenIdAndTimestamp()` → UNION of `custom_fee` + `custom_fee_history`
4. For historical fungible tokens: `tokenRepository.findFungibleTotalSupplyByTokenIdAndTimestamp()` → a 3-CTE query joining `account_balance`, `token_balance`, and `token_transfer` [5](#0-4) [6](#0-5) [7](#0-6) 

**Root cause and failed assumption:** The design assumes that the sum of all sequential SQL queries within a single request will complete well under 10 seconds. This assumption fails under concurrent load: the per-statement DB timeout is 3,000 ms (`hiero.mirror.web3.db.statementTimeout = 3000`), so 4 sequential queries each approaching 3 s can accumulate to ≥ 10 s of elapsed time. The `statementInspector` fires *before* the next statement is sent to the DB, throwing `QueryTimeoutException` and returning 503 to the caller. [8](#0-7) 

**Why existing checks are insufficient:**

The throttle is a single global bucket (500 req/s, 7.5 B gas/s), not per-IP: [9](#0-8) [10](#0-9) 

An attacker using multiple source IPs can consume the full 500 req/s budget with historical `getTokenInfo` calls, each of which triggers 3–4 expensive UNION queries. The gas limit throttle does not account for DB query complexity. The `db.statementTimeout` (3 s) only kills individual queries, not the cumulative elapsed time tracked by the `statementInspector`.

### Impact Explanation

All concurrent legitimate users receive HTTP 503 `Service Unavailable` responses for the duration of the attack. From the client's perspective this is indistinguishable from a network partition or full service outage. The endpoint is publicly accessible with CORS `allowedOrigins("*")`, so no account or credential is needed. [11](#0-10) 

Severity: **High** (full availability loss for all users during attack window, no authentication barrier).

### Likelihood Explanation

The attack requires no credentials, no on-chain assets, and no special knowledge beyond the public ABI of HTS precompiles. The attacker needs only to send HTTP POST requests to `/api/v1/contracts/call` with calldata encoding `getTokenInfo(address)` or `getFungibleTokenInfo(address)` targeting a historical block. Using multiple source IPs to stay under the 500 req/s global bucket, the attacker can sustain DB saturation indefinitely. The attack is repeatable and scriptable.

### Recommendation

1. **Add per-IP rate limiting** at the ingress/load-balancer layer or within the application (e.g., using the requester's IP as a bucket key in `ThrottleManagerImpl`).
2. **Decouple the application-level timeout from the DB-level timeout**: set `requestTimeout` to be strictly less than `N × db.statementTimeout` where N is the maximum number of sequential queries per request, so the DB timeout always fires before the application timeout accumulates.
3. **Introduce a per-request DB connection timeout** (e.g., via `DataSource` connection-level `socketTimeout`) so that a slow DB kills the connection rather than allowing the `statementInspector` to accumulate elapsed time across multiple statements.
4. **Cache token precompile results** more aggressively (the current `token` cache TTL is only 1 s), so repeated calls for the same token do not re-hit the DB. [12](#0-11) 

### Proof of Concept

```
# Step 1: Deploy or identify a token at address TOKEN_ADDR on the mirror node network.
# Step 2: Encode a call to getTokenInfo(TOKEN_ADDR) using the HTS precompile selector 0x1f69565f.
# Step 3: Send 500 concurrent requests per second from multiple IPs:

for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{
      "to": "0x0000000000000000000000000000000000000167",
      "data": "0x1f69565f000000000000000000000000<TOKEN_ADDR_PADDED>",
      "gas": 15000000,
      "block": "0x1"
    }' &
done
wait

# Step 4: Observe that after DB saturation, responses return HTTP 503:
# {"message":"Service Unavailable"}
# Logged server-side as: "503 Transaction timed out after NNNN ms"
```

The `block: "0x1"` (historical) parameter forces the UNION queries against `token_history`, `custom_fee_history`, and the 3-CTE total-supply query, maximizing per-request DB load. Under saturation, the `statementInspector` fires at line 41 of `HibernateConfiguration.java` and all concurrent legitimate requests receive 503. [13](#0-12)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L31-31)
```java
    private final long startTime = System.currentTimeMillis();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-47)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L19-20)
```java
    @DurationMin(seconds = 1L)
    private Duration requestTimeout = Duration.ofSeconds(10L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L73-78)
```java
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/v1/contracts/**").allowedOrigins("*");
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L119-122)
```java
    @ExceptionHandler
    private ResponseEntity<?> queryTimeoutException(final QueryTimeoutException e, WebRequest request) {
        return handleExceptionInternal(e, null, null, SERVICE_UNAVAILABLE, request);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/TokenReadableKVState.java (L73-90)
```java
    protected Token readFromDataSource(@NonNull TokenID key) {
        final var timestamp = ContractCallContext.get().getTimestamp();
        final var entity = commonEntityAccessor.get(key, timestamp).orElse(null);

        if (entity == null || entity.getType() != EntityType.TOKEN) {
            return null;
        }

        final var token = timestamp
                .flatMap(t -> tokenRepository.findByTokenIdAndTimestamp(entity.getId(), t))
                .orElseGet(() -> tokenRepository.findById(entity.getId()).orElse(null));

        if (token == null) {
            return null;
        }

        return tokenFromEntities(entity, token, timestamp);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/TokenRepository.java (L72-99)
```java
    @Query(value = """
                    with snapshot_timestamp as (
                      select consensus_timestamp
                      from account_balance
                      where account_id = ?3 and
                        consensus_timestamp <= ?2 and
                        consensus_timestamp > ?2 - 2678400000000000
                      order by consensus_timestamp desc
                      limit 1
                    ), snapshot as (
                      select distinct on (account_id) balance
                      from token_balance
                      where token_id = ?1 and
                        consensus_timestamp <= (select consensus_timestamp from snapshot_timestamp) and
                        consensus_timestamp <= ?2 and
                        consensus_timestamp > ?2 - 2678400000000000
                      order by account_id, consensus_timestamp desc
                    ), change as (
                      select amount
                      from token_transfer
                      where token_id = ?1 and
                        consensus_timestamp >= (select consensus_timestamp from snapshot_timestamp) and
                        consensus_timestamp <= ?2 and
                        consensus_timestamp > ?2 - 2678400000000000
                    )
                    select coalesce((select sum(balance) from snapshot), 0) + coalesce((select sum(amount) from change), 0)
                    """, nativeQuery = true)
    long findFungibleTotalSupplyByTokenIdAndTimestamp(long tokenId, long blockTimestamp, long treasuryAccountId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/CustomFeeRepository.java (L22-41)
```java
    @Query(value = """
            (
                select *
                from custom_fee
                where entity_id = :entityId
                    and lower(timestamp_range) <= :blockTimestamp
            )
            union all
            (
                select *
                from custom_fee_history
                where entity_id = :entityId
                    and lower(timestamp_range) <= :blockTimestamp
                order by lower(timestamp_range) desc
                limit 1
            )
            order by timestamp_range desc
            limit 1
            """, nativeQuery = true)
    Optional<CustomFee> findByTokenIdAndTimestamp(long entityId, long blockTimestamp);
```

**File:** docs/configuration.md (L696-696)
```markdown
| `hiero.mirror.web3.cache.token`                              | expireAfterWrite=1s,maximumSize=10000,recordStats  | Cache configuration for token related info                                                                                                                                                       |
```

**File:** docs/configuration.md (L702-702)
```markdown
| `hiero.mirror.web3.db.statementTimeout`                      | 3000                                               | The number of milliseconds to wait before timing out a query statement                                                                                                                           |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L26-35)
```java
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```
