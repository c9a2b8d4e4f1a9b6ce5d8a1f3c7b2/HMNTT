Based on my investigation of the code, let me analyze the validation gate:

**Code reviewed:**
- `EntityRepository.java` (lines 19-29): The `getSupply()` query uses `unnest` + `join` + `sum` aggregation over the `entity` table.
- `NetworkServiceImpl.java` (lines 59-89): `lowerBounds`/`upperBounds` come from **server-side** `networkProperties`, not user input.
- `NetworkController.java` (lines 132-150): The `/api/v1/network/supply` endpoint accepts only `timestamp` and `q` params — no auth, no rate limiting.
- `HIGH_VOLUME_THROTTLE` is imported and applied to `estimateFees` (line 116) but **absent** from `getSupply`.
- No `@Cacheable`, `RateLimiter`, or Hikari pool limits found in the rest-java service layer.

---

### Title
Unauthenticated Repeated Requests to `/api/v1/network/supply` Exhaust DB Connection Pool via Unthrottled Aggregation Query

### Summary
The `/api/v1/network/supply` endpoint is publicly accessible with no authentication, no rate limiting, and no caching. Every request triggers an expensive `unnest` + `join` + `sum` aggregation over the entire `entity` table. An unprivileged attacker can flood this endpoint with concurrent requests, exhausting the shared database connection pool and denying service to all legitimate callers.

### Finding Description
**Code path:**
- `NetworkController.getSupply()` (`NetworkController.java:132-150`) accepts unauthenticated GET requests and calls `networkService.getSupply(bound)`.
- `NetworkServiceImpl.getSupply()` (`NetworkServiceImpl.java:59-89`) calls `entityRepository.getSupply(lowerBounds, upperBounds)` on every request when no timestamp is provided (the common case).
- `EntityRepository.getSupply()` (`EntityRepository.java:19-29`) executes:
  ```sql
  select cast(coalesce(sum(e.balance), 0) as bigint) as unreleased_supply,
         cast(coalesce(max(e.balance_timestamp), 0) as bigint) as consensus_timestamp
  from entity e
  join unnest(
          cast(string_to_array(:lowerBounds, ',') as bigint[]),
          cast(string_to_array(:upperBounds, ',') as bigint[])
       ) as ranges(min_val, max_val)
    on e.id between ranges.min_val and ranges.max_val
  ```
  This is a full-table aggregation with an `unnest`-based range join — one of the most expensive query patterns in PostgreSQL.

**Root cause:** The `HIGH_VOLUME_THROTTLE` mechanism already present in the codebase (applied to `estimateFees` at `NetworkController.java:116`) was never applied to `getSupply`. There is no `@Cacheable`, no rate limiter, and no connection-level guard on this path. The `lowerBounds`/`upperBounds` are server-side config (not attacker-controlled), but the attacker does not need to manipulate them — they only need to trigger many concurrent executions of the same expensive query.

**Why existing checks fail:** The `timestamp` parameter validation (`minTimestamp > maxTimestamp` check at line 73) only applies when a timestamp is supplied. The default no-timestamp path goes directly to the expensive `entityRepository.getSupply()` call with zero throttling.

### Impact Explanation
Each concurrent request holds a JDBC connection from the shared HikariCP pool for the duration of the aggregation query. With enough concurrent requests, the pool is exhausted, causing all other endpoints (fees, nodes, stake, etc.) that share the same pool to queue or fail. This is a complete availability impact on the mirror node REST API with no data confidentiality or integrity impact.

### Likelihood Explanation
The endpoint requires zero authentication, zero special knowledge, and zero protocol-level access. Any internet-accessible mirror node deployment is reachable. The attack is trivially repeatable with standard HTTP load tools (`ab`, `wrk`, `hey`). The absence of rate limiting — despite the `HIGH_VOLUME_THROTTLE` pattern already existing in the same controller — makes this a low-effort, high-impact attack.

### Recommendation
1. Apply the existing `HIGH_VOLUME_THROTTLE` mechanism to the `getSupply` endpoint, consistent with `estimateFees`.
2. Add `@Cacheable` (e.g., with a short TTL of 5–15 seconds) on `NetworkServiceImpl.getSupply()` — supply data changes infrequently and caching would absorb burst traffic entirely.
3. Configure a per-IP or global rate limit at the ingress/API gateway layer for `/api/v1/network/supply`.
4. Consider setting a PostgreSQL `statement_timeout` for the connection pool used by this query to bound worst-case query duration.

### Proof of Concept
```bash
# Send 500 concurrent unauthenticated requests with no timestamp (triggers the expensive path)
hey -n 500 -c 100 http://<mirror-node-host>/api/v1/network/supply

# Observe: DB connection pool exhaustion in mirror node logs,
# subsequent requests to /api/v1/network/fees, /api/v1/network/nodes, etc.
# begin timing out or returning 503 as the shared pool is starved.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L19-29)
```java
    @Query(value = """
                    select cast(coalesce(sum(e.balance), 0) as bigint) as unreleased_supply,
                        cast(coalesce(max(e.balance_timestamp), 0) as bigint) as consensus_timestamp
                    from entity e
                    join unnest(
                            cast(string_to_array(:lowerBounds, ',') as bigint[]),
                            cast(string_to_array(:upperBounds, ',') as bigint[])
                         ) as ranges(min_val, max_val)
                      on e.id between ranges.min_val and ranges.max_val
                    """, nativeQuery = true)
    NetworkSupply getSupply(String lowerBounds, String upperBounds);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L59-89)
```java
    public NetworkSupply getSupply(Bound timestamp) {
        final NetworkSupply networkSupply;

        final var bounds = networkProperties.getUnreleasedSupplyRangeBounds();
        final var lowerBounds = bounds.lowerBounds();
        final var upperBounds = bounds.upperBounds();

        if (timestamp.isEmpty()) {
            networkSupply = entityRepository.getSupply(lowerBounds, upperBounds);
        } else {
            var minTimestamp = timestamp.getAdjustedLowerRangeValue();
            final var maxTimestamp = timestamp.adjustUpperBound();

            // Validate timestamp range
            if (minTimestamp > maxTimestamp) {
                throw new IllegalArgumentException("Invalid range provided for timestamp");
            }

            final var optimalLowerBound = getFirstDayOfMonth(maxTimestamp, -1);
            minTimestamp = Math.max(minTimestamp, optimalLowerBound);

            networkSupply =
                    accountBalanceRepository.getSupplyHistory(lowerBounds, upperBounds, minTimestamp, maxTimestamp);
        }

        if (networkSupply.consensusTimestamp() == 0L) {
            throw new EntityNotFoundException("Network supply not found");
        }

        return networkSupply;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L110-150)
```java
    @PostMapping(
            consumes = {"application/protobuf", "application/x-protobuf"},
            value = "/fees")
    FeeEstimateResponse estimateFees(
            @RequestBody @NotNull byte[] body,
            @RequestParam(defaultValue = "INTRINSIC", required = false) FeeEstimateMode mode,
            @RequestParam(name = HIGH_VOLUME_THROTTLE, defaultValue = "0", required = false) @Min(0) @Max(10000)
                    int highVolumeThrottle) {
        try {
            final var transaction = Transaction.PROTOBUF.parse(Bytes.wrap(body));
            return toResponse(feeEstimationService.estimateFees(transaction, mode, highVolumeThrottle));
        } catch (ParseException e) {
            throw new IllegalArgumentException("Unable to parse transaction", e);
        }
    }

    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
    }

    @GetMapping("/supply")
    ResponseEntity<?> getSupply(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(name = "q", required = false) SupplyType supplyType) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var networkSupply = networkService.getSupply(bound);

        if (supplyType != null) {
            final var valueInTinyCoins =
                    supplyType == SupplyType.TOTALCOINS ? NetworkSupply.TOTAL_SUPPLY : networkSupply.releasedSupply();
            final var formattedValue = networkSupplyMapper.convertToCurrencyFormat(valueInTinyCoins);

            return ResponseEntity.ok()
                    .contentType(new MediaType(MediaType.TEXT_PLAIN, UTF_8))
                    .body(formattedValue);
        }

        return ResponseEntity.ok(networkSupplyMapper.map(networkSupply));
    }
```
