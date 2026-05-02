### Title
Unauthenticated Historical Block Queries Exhaust DB Connection Pool via Unthrottled Per-IP Gas Restoration

### Summary
Any unauthenticated caller can POST to `/api/v1/contracts/call` with an arbitrary historical `block` number. The global throttle (500 req/s, gas-based) is effectively bypassed because gas tokens are fully restored on failed/reverted calls (`gasLimitRefundPercent = 100` default). A single attacker can saturate the global 500 req/s budget, each request triggering multiple DB queries against `*_history` tables, exhausting the finite HikariCP connection pool and severing the web3 service from its data layer.

### Finding Description

**Exact code path:**

`ContractController.call()` (line 38–51) accepts any `block` value with no minimum-age or range validation: [1](#0-0) 

`BlockType.of()` accepts any non-negative long, including block 0 (genesis): [2](#0-1) 

The throttle is a **single global bucket** — not per-IP — with a default of 500 req/s: [3](#0-2) 

Gas tokens are consumed upfront but **fully restored** on any non-`InvalidParametersException` outcome (revert, block-not-found, etc.) via `restoreGasToBucket` in the `finally` block: [4](#0-3) 

`gasLimitRefundPercent` defaults to 100, meaning all consumed gas tokens are returned: [5](#0-4) 

**Root cause — failed assumption:** The design assumes the gas throttle will bound DB load. In practice, gas is fully restored for failed calls, so the only binding constraint is the 500 req/s global request-rate bucket. That bucket is shared across all callers with no per-IP subdivision.

**Historical state DB load per request:** Each historical call resolves the record file via `findByIndex`, then during EVM execution lazily issues one DB query per accessed account, token, NFT, custom fee, storage slot, etc., all against `*_history` tables: [6](#0-5) [7](#0-6) 

### Impact Explanation

At 500 req/s, if each historical call holds a HikariCP connection for even 50 ms (realistic for a multi-join history query), ~25 concurrent connections are needed. Spring Boot's default HikariCP pool is 10 connections. Once the pool is exhausted, all subsequent DB operations — including those serving legitimate traffic and the importer — queue or time out. This constitutes a full data-layer partition for the web3 service, causing cascading 500 errors for all users.

### Likelihood Explanation

No authentication, API key, or per-IP rate limit is required. A single attacker with a modest HTTP client (e.g., `wrk`, `ab`) can trivially sustain 500 req/s from one machine. The attack is stateless, repeatable, and requires no knowledge of contract addresses — sending `to: Address.ZERO` with `block: 1` is sufficient to trigger historical DB queries. The gas restoration loop means the gas bucket never depletes, so the attack sustains indefinitely.

### Recommendation

1. **Add per-IP rate limiting** in addition to the global bucket (e.g., via Spring Cloud Gateway, a servlet filter, or bucket4j's per-key API).
2. **Do not restore gas on historical calls that fail due to missing block** — treat `BlockNumberNotFoundException` as a consumed-gas event, not a refund event.
3. **Enforce a minimum block age or a configurable `historicalBlocksEnabled` flag** to optionally disable historical queries entirely.
4. **Set a DB query timeout** specific to the web3 datasource (e.g., HikariCP `connectionTimeout` + statement timeout) so long-running history queries release connections promptly.
5. **Separate the historical-query connection pool** from the live-state pool so historical DoS cannot starve current-state lookups.

### Proof of Concept

```bash
# Attacker sends 500 req/s of historical block-0 calls with minimum gas
# No auth required; gas is fully restored after each failed/reverted call

wrk -t4 -c50 -d60s -s post.lua http://<mirror-node>:8545/api/v1/contracts/call
```

`post.lua`:
```lua
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"block":"0x1","to":"0x0000000000000000000000000000000000000167","gas":21000,"data":"0x"}'
```

**Expected result:** Within seconds, HikariCP connection pool exhausts; all subsequent `/api/v1/contracts/call` requests (and any other DB-dependent endpoint) return HTTP 500 or hang until connection timeout. The web3 service is effectively partitioned from its database.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-51)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L37-55)
```java
    private static BlockType extractNumericBlock(String value) {
        int radix = 10;
        var cleanedValue = value;

        if (value.startsWith(HEX_PREFIX)) {
            radix = 16;
            cleanedValue = Strings.CS.removeStart(value, HEX_PREFIX);
        }

        if (cleanedValue.contains(NEGATIVE_NUMBER_PREFIX)) {
            throw new IllegalArgumentException("Invalid block value: " + value);
        }

        try {
            long blockNumber = Long.parseLong(cleanedValue, radix);
            return new BlockType(value, blockNumber);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid block value: " + value, e);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L22-22)
```java
    private float gasLimitRefundPercent = 100;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-36)
```java
    @Min(1)
    private long requestsPerSecond = 500;

```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L100-107)
```java
    protected final EvmTransactionResult callContract(CallServiceParameters params, ContractCallContext ctx)
            throws MirrorEvmTransactionException {
        ctx.setCallServiceParameters(params);
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));

        return doProcessCall(params, params.getGas(), false);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L127-135)
```java
        } finally {
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());

                // Only record metric if EVM is invoked and not inside estimate loop
                if (result != null) {
                    updateMetrics(params, result.gasUsed(), 1, status);
                }
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L136-154)
```java
    @Query(value = """
                    (
                        select *
                        from entity
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                    )
                    union all
                    (
                        select *
                        from entity_history
                        where id = ?1 and lower(timestamp_range) <= ?2
                        and deleted is not true
                        order by lower(timestamp_range) desc
                        limit 1
                    )
                    order by timestamp_range desc
                    limit 1
                    """, nativeQuery = true)
```
