### Title
Unauthenticated Repeated Historical Supply Queries Cause Database Resource Exhaustion (DoS)

### Summary
The public `GET /api/v1/network/supply` endpoint accepts a user-controlled `timestamp` parameter. When non-empty, `NetworkServiceImpl.getSupply()` unconditionally executes a complex native SQL aggregation query (`getSupplyHistory`) against the `account_balance` table on every request, with no caching and no rate limiting. An unprivileged attacker can flood this endpoint with varying timestamps to exhaust database CPU and I/O, degrading or denying service to the mirror node REST API.

### Finding Description

**Code path:**

`NetworkController.getSupply()` [1](#0-0)  accepts `timestamp` from any unauthenticated caller and passes it to `NetworkServiceImpl.getSupply()`.

Inside `getSupply()`, when `timestamp` is non-empty the code takes the historical branch: [2](#0-1) 

The only mitigation is `optimalLowerBound`, which clamps the lower timestamp to the first day of the previous calendar month: [3](#0-2) 

This limits the scan window to ~1–2 months of data but does **not** prevent repeated execution. The query itself is a full aggregation over that window: [4](#0-3) 

It uses `DISTINCT ON (ab.account_id)`, a `JOIN unnest(...)` with array parameters, a `WHERE consensus_timestamp BETWEEN` range scan, and a `SUM(balance)` — all on a potentially large `account_balance` table.

**Root cause:** No `@Cacheable` annotation exists on `getSupply()` or `getSupplyHistory()`, and no rate limiting is applied to the `/network/supply` endpoint (unlike the fee-estimation endpoint which has `HIGH_VOLUME_THROTTLE`). [5](#0-4) 

**Why existing checks fail:** The `minTimestamp > maxTimestamp` guard only rejects logically invalid ranges. The `optimalLowerBound` clamp reduces query scope but still allows a full month-wide aggregation scan on every single request. An attacker who varies `maxTimestamp` by even 1 nanosecond per request defeats any future result-level caching. [6](#0-5) 

### Impact Explanation
Repeated concurrent requests force the database to execute expensive aggregation queries continuously. This exhausts database CPU and I/O, slowing or blocking all other mirror node queries (including the importer's write path). The mirror node REST API becomes unavailable. Note: the Hedera consensus network itself is unaffected — the "total network shutdown" label in the question is overstated — but the mirror node service is fully deniable.

### Likelihood Explanation
Preconditions: none. Any internet-accessible client can call `GET /api/v1/network/supply?timestamp=lte:<value>`. The attacker needs only to vary the timestamp value across requests (e.g., decrement by 1 nanosecond each time) to ensure no result reuse. The attack is trivially scriptable with `curl` or any HTTP load tool and requires no credentials, tokens, or special knowledge.

### Recommendation
1. **Add response caching** with a short TTL (e.g., 5–15 seconds) on `NetworkServiceImpl.getSupply()` using Spring's `@Cacheable`, keyed on the resolved `(minTimestamp, maxTimestamp)` pair after the `optimalLowerBound` clamp is applied — not on raw user input.
2. **Apply rate limiting** to `GET /api/v1/network/supply` (similar to the `HIGH_VOLUME_THROTTLE` mechanism already present on the fee endpoint).
3. **Add a database query timeout** on `getSupplyHistory` so a single slow query cannot hold a connection indefinitely.
4. Consider **further constraining the timestamp window** (e.g., reject requests for timestamps older than N days) to bound worst-case query cost.

### Proof of Concept
```bash
# Flood the endpoint with slightly varying timestamps (no auth required)
for i in $(seq 1 500); do
  TS=$((1700000000000000000 - i))
  curl -s "https://<mirror-node-host>/api/v1/network/supply?timestamp=lte:${TS}" &
done
wait
# Observe: database CPU spikes to 100%, subsequent queries time out,
# mirror node REST API returns 503 or hangs.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L132-137)
```java
    @GetMapping("/supply")
    ResponseEntity<?> getSupply(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(name = "q", required = false) SupplyType supplyType) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var networkSupply = networkService.getSupply(bound);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/AccountBalanceRepository.java (L12-28)
```java
    @Query(value = """
    with account_balances as (
      select distinct on (ab.account_id) ab.balance, ab.consensus_timestamp
      from account_balance ab
      join unnest(
            cast(string_to_array(:lowerBounds, ',') as bigint[]),
            cast(string_to_array(:upperBounds, ',') as bigint[])
         ) as ranges(min_val, max_val)
      on ab.account_id between ranges.min_val and ranges.max_val
      where ab.consensus_timestamp between :lowerTimestamp and :upperTimestamp
      order by ab.account_id asc, ab.consensus_timestamp desc
    )
    select cast(coalesce(sum(balance), 0) as bigint) as unreleased_supply,
           coalesce(max(consensus_timestamp), 0) as consensus_timestamp
    from account_balances
    """, nativeQuery = true)
    NetworkSupply getSupplyHistory(String lowerBounds, String upperBounds, long lowerTimestamp, long upperTimestamp);
```
