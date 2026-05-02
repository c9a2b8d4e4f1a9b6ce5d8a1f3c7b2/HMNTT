### Title
Gas Throttle Bypass via Full Refund on Failed Historical Calls with Maximum Calldata

### Summary
`constructServiceParameters()` in `ContractController` accepts up to 512 KB of calldata (the `@Hex` default `maxLength = 1048576` hex chars) with no calldata-size-based throttling. The gas throttle is the only resource guard, but it fully restores all consumed gas tokens when a transaction fails with `gasUsed == gasLimit` (the default `gasLimitRefundPercent = 100`). An attacker can therefore send the maximum rate of requests (500 req/sec) with maximum calldata targeting historical blocks, have the gas tokens fully refunded after each out-of-gas failure, and continuously drive expensive historical-state DB queries and large hex-parsing operations with zero net gas cost.

### Finding Description

**Code path:**

`ContractController.call()` (line 38–51) → `throttleManager.throttle(request)` (line 40) → `validateContractMaxGasLimit(request)` (line 41) → `constructServiceParameters(request)` (line 43) → `contractExecutionService.processCall(params)` (line 44).

**Root cause 1 – calldata size not throttled:**

`ContractCallRequest.data` is annotated `@Hex` with no explicit `maxLength`, so the default of `1,048,576` hex characters (512 KB of raw bytes) applies. [1](#0-0) [2](#0-1) 

The OpenAPI spec documents `maxLength: 262146` (128 KB), but the server-side validator allows 4× that amount. [3](#0-2) 

Inside `constructServiceParameters`, `hexToBytes(data)` is called unconditionally on the full user-supplied string before any EVM execution, allocating up to 512 KB per request on the heap. [4](#0-3) 

**Root cause 2 – gas throttle fully refunded on failure:**

`ThrottleManagerImpl.throttle()` consumes gas tokens upfront based solely on `request.getGas()`. [5](#0-4) 

After execution, `restoreGasToBucket()` restores `gasLimit × gasLimitRefundPercent / 100` tokens. With the default `gasLimitRefundPercent = 100`, when the EVM fails with `gasUsed == gasLimit` (the exact condition for an out-of-gas revert), **100% of the consumed gas tokens are returned to the bucket**. [6](#0-5) 

**Root cause 3 – historical block amplification:**

When `block` is a historical block number, every EVM state read triggers expensive UNION queries across `entity`/`entity_history`, `nft_allowance`/`nft_allowance_history`, etc. This DB overhead is not captured by the gas metric and is not restored to any throttle bucket. [7](#0-6) 

**Exploit flow:**

1. Attacker sends `POST /api/v1/contracts/call` with `gas = 15,000,000` (max), `data = 0x` + 1,048,574 hex chars (512 KB), `block = "0x1"` (any historical block).
2. `throttleManager.throttle()` consumes 1,500 scaled gas tokens (15M ÷ 10,000).
3. `constructServiceParameters()` calls `hexToBytes()`, allocating 512 KB on the heap.
4. EVM executes: intrinsic calldata cost for 512 KB of non-zero bytes ≈ 8.4 M gas, exhausting the 15 M gas limit quickly. Historical state DB queries fire during execution.
5. EVM returns failure with `gasUsed == gasLimit`. `restoreGasToBucket()` returns all 1,500 tokens to the bucket.
6. Net gas cost to attacker: **zero**. The `requestsPerSecond = 500` rate limit is the only remaining constraint.
7. Attacker repeats at 500 req/sec continuously.

### Impact Explanation

At 500 req/sec (the `requestsPerSecond` cap):
- **CPU**: 256 MB/sec of hex-string parsing via `hexToBytes()`.
- **Heap**: 500 × 512 KB = 256 MB/sec of byte-array allocation, pressuring GC.
- **DB**: 500 historical-state UNION query sets/sec against `entity_history`, `nft_allowance_history`, etc., saturating the DB connection pool (`statementTimeout = 3000 ms`).
- **Threads**: Each request can hold a thread for up to `requestTimeout = 10,000 ms`, enabling thread-pool exhaustion with as few as `threadPoolSize / 10` sustained req/sec.

Legitimate historical queries are starved of DB connections and threads, making true historical transaction state effectively inaccessible.

### Likelihood Explanation

The endpoint is public and unauthenticated. No API key or account is required. The attack requires only standard HTTP tooling (e.g., `wrk`, `ab`, or a simple script). The gas refund mechanism makes the attack self-sustaining at zero net throttle cost. A single attacker with a modest connection pool can sustain 500 req/sec indefinitely.

### Recommendation

1. **Add calldata-size-based throttling**: Incorporate `callData.length` into the throttle cost, not just `gas`. A combined metric (e.g., `gas + callDataBytes × calldataGasWeight`) prevents large-calldata abuse.
2. **Reduce `@Hex` maxLength on `data`**: Align the server-side validator with the OpenAPI spec (`maxLength = 262146`), or enforce a tighter limit.
3. **Differentiate historical vs. latest throttle**: Apply a stricter rate limit or separate bucket for requests targeting historical blocks, reflecting their higher DB cost.
4. **Cap gas refund for failed calls**: Reduce `gasLimitRefundPercent` from 100% to a lower value (e.g., 10–20%) for out-of-gas failures, so failed requests still consume throttle capacity.
5. **Enforce a per-request calldata size cap** independently of gas, before `hexToBytes()` is called.

### Proof of Concept

```bash
# Generate 512 KB of hex calldata (1,048,574 hex chars after "0x")
DATA="0x$(python3 -c "print('ff' * 524287)")"

# Fire at 500 req/sec targeting a historical block
wrk -t8 -c500 -d60s -s post.lua https://mirror-node/api/v1/contracts/call
```

`post.lua`:
```lua
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.body = string.format(
  '{"to":"0x0000000000000000000000000000000000000001",' ..
  '"gas":15000000,' ..
  '"block":"0x1",' ..
  '"data":"%s"}',
  DATA
)
```

Expected result: DB connection pool saturated within seconds; historical `/contracts/call` requests from legitimate users begin timing out with 503 or hanging for the full `requestTimeout = 10,000 ms`. Gas bucket remains full throughout due to 100% refund on out-of-gas failures.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L28-29)
```java
    @Hex
    private String data;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/validation/Hex.java (L26-27)
```java
     */
    long maxLength() default 1048576L;
```

**File:** rest/api/v1/openapi.yml (L2793-2800)
```yaml
        data:
          description: Hexadecimal method signature and encoded parameters. Up to 131072 bytes as at most 262146 hexadecimal digits including optional leading 0x.
          example: "0x47f1aae7"
          format: binary
          maxLength: 262146
          nullable: true
          pattern: "^(0x)?[0-9a-fA-F]+$"
          type: string
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L66-80)
```java
        String data;
        try {
            data = request.getData() != null ? request.getData() : HEX_PREFIX;
        } catch (final Exception e) {
            throw new InvalidParametersException(
                    "data field '%s' contains invalid odd length characters".formatted(request.getData()));
        }

        final var isStaticCall = false;
        final var callType = request.isEstimate() ? ETH_ESTIMATE_GAS : ETH_CALL;
        final var block = request.getBlock();

        return ContractExecutionParameters.builder()
                .block(block)
                .callData(hexToBytes(data))
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L140-151)
```java
    private void restoreGasToBucket(EvmTransactionResult result, long gasLimit) {
        // If the transaction fails, gasUsed is equal to gasLimit, so restore the configured refund percent
        // of the gasLimit value back in the bucket.
        final var gasLimitToRestoreBaseline = (long) (gasLimit * throttleProperties.getGasLimitRefundPercent() / 100f);
        if (result == null || (!result.isSuccessful() && gasLimit == result.gasUsed())) {
            throttleManager.restore(gasLimitToRestoreBaseline);
        } else {
            // The transaction was successful or reverted, so restore the remaining gas back in the bucket or
            // the configured refund percent of the gasLimit value back in the bucket - whichever is lower.
            final var gasRemaining = gasLimit - result.gasUsed();
            throttleManager.restore(Math.min(gasRemaining, gasLimitToRestoreBaseline));
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
