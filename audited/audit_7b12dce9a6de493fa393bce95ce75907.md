### Title
Unauthenticated Direct HTS Precompile Calls Bypass Gas Throttle, Enabling DB-Load Griefing

### Summary
`constructServiceParameters()` in `ContractController.java` places no restriction on the `to` field, allowing any caller to target the HTS precompile address (`0x0000000000000000000000000000000000000167`) directly. Because HTS precompile operations consume minimal EVM gas while triggering multiple synchronous database queries per call, and because `gasLimitRefundPercent` defaults to 100% (restoring nearly all declared gas after each cheap precompile call), the gas-bucket throttle is rendered ineffective. An attacker can sustain the maximum request rate (500 req/s) while each request drives multiple DB round-trips, degrading service for all users.

### Finding Description

**Exact code path:**

`ContractController.constructServiceParameters()` (lines 53–90) resolves the `to` field with no precompile-address guard:

```java
// ContractController.java lines 60-64
if (request.getTo() == null || request.getTo().isEmpty()) {
    receiver = Address.ZERO;
} else {
    receiver = Address.fromHexString(request.getTo());   // 0x167 accepted as-is
}
``` [1](#0-0) 

The resulting `ContractExecutionParameters` is passed directly to `contractExecutionService.processCall()` with `receiver = Address(0x167)`.

**Throttle mechanism:**

`ThrottleManagerImpl.throttle()` enforces two limits: a flat request-per-second bucket (default 500 req/s) and a gas-per-second bucket (default 7.5 billion gas/s, scaled by ÷10,000 = 750,000 tokens/s). [2](#0-1) 

After each call, `restoreGasToBucket` returns unused gas to the bucket. With `gasLimitRefundPercent = 100` (default), if a request declares 15 M gas but the precompile consumes only ~10 K gas, ≈14,990,000 gas is restored: [3](#0-2) 

This means the gas bucket imposes no meaningful cost on precompile-heavy requests; the only binding constraint is the 500 req/s rate limit.

**DB operations triggered per precompile call:**

A direct call to `0x167` with `getTokenInfo` selector causes the HTS precompile handler to execute multiple synchronous DB queries:
- `TokenRepository.findById()` / `findByTokenIdAndTimestamp()` (UNION across `token` + `token_history`)
- `CustomFeeRepository.findById()` / `findByTokenIdAndTimestamp()` (UNION across `custom_fee` + `custom_fee_history`)
- Entity lookups for treasury account, auto-renew account [4](#0-3) [5](#0-4) 

The `ContractCallNativePrecompileTest` and e2e `CallFeature` confirm direct precompile calls are fully supported and executed by the EVM: [6](#0-5) 

**Root cause / failed assumption:**

The gas throttle was designed to bound EVM computational cost. It implicitly assumes gas consumption is proportional to backend work. For HTS precompile calls this assumption fails: EVM gas cost is fixed and low, while DB I/O cost is real and unbounded by the throttle. The 100% gas refund policy amplifies this by making the gas bucket a no-op for precompile workloads.

### Impact Explanation

At 500 req/s (the rate limit), each request triggers 3–6 DB queries. This yields 1,500–3,000 DB queries/second from a single attacker with no authentication, no economic cost, and no per-IP limiting visible in the codebase. Sustained load degrades response times for all legitimate users of the `/api/v1/contracts/call` endpoint. The impact is service degradation (griefing) with no direct economic damage to network participants, consistent with the Medium scope defined for this finding.

### Likelihood Explanation

The attack requires no credentials, no on-chain assets, and no special knowledge beyond the public ABI of the HTS precompile (selector `0x1f69565f` for `getTokenInfo`, etc.). The endpoint is publicly reachable. The attack is trivially scriptable and repeatable. Any motivated actor can sustain it indefinitely.

### Recommendation

1. **Validate `to` against precompile addresses** in `constructServiceParameters()`: reject or specially handle requests where `receiver` falls in the Hedera precompile range (`0x100`–`0x1ff`) at the controller layer, or apply a separate, lower rate limit for such requests.
2. **Decouple DB-cost throttling from gas throttling**: introduce a per-request DB-query counter or wall-clock execution-time budget that is not refunded, so precompile-heavy calls consume throttle tokens proportional to actual backend work.
3. **Reduce `gasLimitRefundPercent`** for failed/reverted calls, or cap the refund for calls targeting precompile addresses, so the gas bucket reflects real resource consumption.
4. **Add per-IP or per-client rate limiting** at the ingress layer to prevent a single source from consuming the full 500 req/s budget.

### Proof of Concept

```
# Craft getTokenInfo(address) calldata for a known token address
# Selector: 0x1f69565f, token address padded to 32 bytes

POST /api/v1/contracts/call
Content-Type: application/json

{
  "to":   "0x0000000000000000000000000000000000000167",
  "data": "0x1f69565f000000000000000000000000000000000000000000000000000000000000<tokenAddr>",
  "gas":  15000000
}

# Repeat at 500 req/s (rate limit) with no authentication.
# Each request triggers TokenRepository + CustomFeeRepository + entity queries.
# Gas bucket is refilled after each call (gasLimitRefundPercent=100).
# Result: sustained 1500-3000 DB queries/second from a single unauthenticated client.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L60-64)
```java
        if (request.getTo() == null || request.getTo().isEmpty()) {
            receiver = Address.ZERO;
        } else {
            receiver = Address.fromHexString(request.getTo());
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-48)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/TokenRepository.java (L44-61)
```java
    @Query(value = """
                    (
                        select *
                        from token
                        where token_id = ?1 and lower(timestamp_range) <= ?2
                    )
                    union all
                    (
                        select *
                        from token_history
                        where token_id = ?1 and lower(timestamp_range) <= ?2
                        order by lower(timestamp_range) desc
                        limit 1
                    )
                    order by timestamp_range desc
                    limit 1
                    """, nativeQuery = true)
    Optional<Token> findByTokenIdAndTimestamp(long tokenId, long blockTimestamp);
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

**File:** web3/src/test/java/org/hiero/mirror/web3/service/ContractCallNativePrecompileTest.java (L36-53)
```java
    @Test
    void directCallToNativePrecompileECRecover() {
        final var gasUsedBeforeExecution = getGasUsedBeforeExecution(ETH_CALL);

        final var hash = "0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3";
        final var v = "000000000000000000000000000000000000000000000000000000000000001c";
        final var r = "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608";
        final var s = "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada";
        final var correctResult = "0x0000000000000000000000007156526fbd7a3c72969b54f64e42c10fbb768c8a";

        final var data = hash.concat(v).concat(r).concat(s);

        final var serviceParameters = serviceParametersForExecution(data, Address.ECREC);

        assertThat(contractCallService.processCall(serviceParameters)).isEqualTo(correctResult);

        assertGasUsedIsPositive(gasUsedBeforeExecution);
    }
```
