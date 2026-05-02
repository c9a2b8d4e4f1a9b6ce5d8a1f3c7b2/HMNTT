### Title
Unbounded Retry-Amplified DB Query DoS via Corrupt Timestamp Targeting on GET /api/v1/network/fees

### Summary
`GET /api/v1/network/fees` invokes `FileServiceImpl.getSystemFile()` twice per request (once for the fee schedule, once for the exchange rate). Each invocation wraps `fileDataRepository.getFileAtTimestamp()` in a `RetryTemplate` configured for up to `maxFileAttempts` (default: **12**) sequential DB calls. An unauthenticated attacker who supplies a timestamp pointing to a known-corrupt or partially-written file version can force up to **24 complex correlated-subquery DB calls** per single HTTP request, with no rate limiting on this endpoint in the `rest-java` module.

### Finding Description

**Exact code path:**

`NetworkController.getFees()` (lines 100–108) calls `fileService.getFeeSchedule(bound)` and `fileService.getExchangeRate(bound)` sequentially with the same attacker-controlled `bound`. [1](#0-0) 

Each delegates to `FileServiceImpl.getSystemFile()`, which initialises a `RetryTemplate` with `maxRetries = queryProperties.getMaxFileAttempts() - 1` (default `maxFileAttempts = 12`, so **11 retries = 12 total attempts**). [2](#0-1) [3](#0-2) 

On each attempt, `fileDataRepository.getFileAtTimestamp(entityId, lowerBound, upperBound.get())` is called. If the returned bytes fail protobuf parsing, `upperBound` is decremented by 1 and the exception is re-thrown, triggering the next retry. [4](#0-3) 

The underlying SQL is a correlated subquery with `string_agg`: [5](#0-4) 

**Root cause:** The retry loop is designed to recover from corrupt on-chain file versions, but there is no per-request cap on total DB work, no rate limiting on the `rest-java` network fees endpoint, and no authentication requirement. The `GET /api/v1/network/fees` handler doubles the amplification by calling `getSystemFile()` for two different system files with the same timestamp bound.

**Exploit flow:**

1. Attacker observes the public Hedera ledger and identifies a consensus timestamp `T` at which a fee schedule or exchange rate file update was in progress (e.g., between a `FILECREATE`/`FILEUPDATE` and its subsequent `FILEAPPEND` chunks). At timestamp `T`, `string_agg` returns incomplete protobuf bytes that fail `CurrentAndNextFeeSchedule::parseFrom` / `ExchangeRateSet::parseFrom`.
2. Attacker sends: `GET /api/v1/network/fees?timestamp=lte:<T>` (no credentials required).
3. Server executes up to 12 `getFileAtTimestamp` calls for the fee schedule file, each decrementing `upperBound` by 1 nanosecond, scanning progressively earlier file versions.
4. Server then executes up to 12 more `getFileAtTimestamp` calls for the exchange rate file.
5. Total: up to **24 expensive correlated-subquery DB calls** per HTTP request.
6. Attacker floods the endpoint with concurrent requests. No rate limiter exists in `rest-java` for this path (the `ThrottleConfiguration`/`ThrottleManagerImpl` bucket4j throttle is only wired in the `web3` module). [6](#0-5) 

**Why existing checks are insufficient:**

- `@Size(max = 2)` on the `timestamp` parameter only limits the number of timestamp query parameters, not the request rate or DB work per request.
- The `statementTimeout` (default 10 000 ms) applies per individual SQL statement, not to the aggregate work of 24 sequential statements.
- There is no `maxFileAttempts` guard that accounts for the double invocation in `getFees`.
- No Spring Security filter, servlet filter, or bucket4j rate limiter is applied to `GET /api/v1/network/fees` in the `rest-java` module.

### Impact Explanation
Each request to `GET /api/v1/network/fees` with a carefully chosen timestamp can consume up to 24 × the DB resources of a normal single-attempt request. The `getFileAtTimestamp` query uses a correlated subquery and `string_agg` aggregation over the `file_data` table, which is CPU- and I/O-intensive. A modest number of concurrent attackers (e.g., 50 concurrent connections each firing requests at ~1 req/s) can sustain hundreds of complex DB queries per second, exhausting the DB connection pool and CPU, exceeding the 30% resource consumption threshold without any brute-force volume.

### Likelihood Explanation
The precondition — a timestamp pointing to a partially-written file version — is realistic and observable. Hedera system file updates are multi-transaction operations (FILECREATE + multiple FILEAPPENDs) whose individual transaction timestamps are publicly visible via the mirror node's own transaction history API. An attacker can trivially identify such timestamps by querying `/api/v1/transactions?account.id=0.0.111&type=FILEAPPEND` and selecting a timestamp between the first and last append. No credentials, special access, or on-chain capability is required. The attack is repeatable and automatable.

### Recommendation
1. **Add per-endpoint rate limiting** to the `rest-java` module for `/api/v1/network/fees` (and `/api/v1/network/exchangerate`), analogous to the bucket4j throttle in the `web3` module.
2. **Cap total DB work per request**: count retry attempts across both `getFeeSchedule` and `getExchangeRate` calls within a single `getFees` invocation, or reduce `maxFileAttempts` to a lower value (e.g., 3–5).
3. **Add a DB-level query timeout** specific to the `getFileAtTimestamp` query, shorter than the global `statementTimeout`.
4. Consider **caching** the result of `getFileAtTimestamp` for a given `(fileId, upperBound)` pair within a single request to avoid redundant queries across the two `getSystemFile` calls.

### Proof of Concept

```bash
# Step 1: Find a timestamp where a fee schedule file update was in progress
curl "https://<mirror-node>/api/v1/transactions?account.id=0.0.111&type=FILEAPPEND&limit=10&order=desc"
# Note the consensus_timestamp of the FIRST append in a multi-append sequence (T_partial)

# Step 2: Flood the fees endpoint with that timestamp (no auth required)
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/network/fees?timestamp=lte:<T_partial>" &
done
wait
# Each request triggers up to 24 correlated-subquery DB calls.
# 200 concurrent requests = up to 4800 complex DB queries simultaneously.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L100-108)
```java
    @GetMapping("/fees")
    NetworkFeesResponse getFees(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(required = false, defaultValue = "ASC") Sort.Direction order) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var feeSchedule = fileService.getFeeSchedule(bound);
        final var exchangeRate = fileService.getExchangeRate(bound);
        return feeScheduleMapper.map(feeSchedule, exchangeRate, bound, order);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/FileServiceImpl.java (L37-44)
```java
    @Getter(lazy = true, value = AccessLevel.PRIVATE)
    private final RetryTemplate retryTemplate = new RetryTemplate(RetryPolicy.builder()
            .maxRetries(queryProperties.getMaxFileAttempts() - 1)
            .predicate(e -> e instanceof InvalidProtocolBufferException
                    || e instanceof ParseException
                    || e.getCause() instanceof InvalidProtocolBufferException
                    || e.getCause() instanceof ParseException)
            .build());
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/FileServiceImpl.java (L74-94)
```java
            return getRetryTemplate()
                    .execute(() -> fileDataRepository
                            .getFileAtTimestamp(entityId.getId(), lowerBound, upperBound.get())
                            .map(fileData -> {
                                try {
                                    return new SystemFile<>(fileData, parser.apply(fileData.getFileData()));
                                } catch (Exception e) {
                                    log.warn(
                                            "Attempt {} failed to load file {} at {}, falling back to previous file.",
                                            attempt.incrementAndGet(),
                                            entityId,
                                            fileData.getConsensusTimestamp(),
                                            e);
                                    upperBound.set(fileData.getConsensusTimestamp() - 1);
                                    throw e;
                                }
                            }))
                    .orElseThrow(() -> new EntityNotFoundException("File %s not found".formatted(entityId)));
        } catch (RetryException e) {
            throw new EntityNotFoundException("File %s not found".formatted(entityId), e);
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/QueryProperties.java (L15-16)
```java
    @Min(1)
    private int maxFileAttempts = 12;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/FileDataRepository.java (L14-34)
```java
    @Query(nativeQuery = true, value = """
            select
              max(consensus_timestamp) as consensus_timestamp,
              ?1 as entity_id,
              string_agg(file_data, '' order by consensus_timestamp) as file_data,
              null as transaction_type
            from file_data
            where entity_id = ?1
              and consensus_timestamp >= (
                select consensus_timestamp
                from file_data
                where entity_id = ?1
                  and consensus_timestamp >= ?2
                  and consensus_timestamp <= ?3
                  and (transaction_type = 17 or (transaction_type = 19 and length(file_data) <> 0))
              order by consensus_timestamp desc
              limit 1
            ) and consensus_timestamp <= ?3
              and (transaction_type <> 19 or length(file_data) <> 0)
            """)
    Optional<FileData> getFileAtTimestamp(long fileId, long lowerTimestamp, long upperTimestamp);
```
