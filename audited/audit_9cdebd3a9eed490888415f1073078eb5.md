### Title
Gas Throttle Bypass via Non-Existent Alias Addresses Enables Sustained Database Lookup Amplification

### Summary
`getSenderAccountIDAsNum()` performs a live database lookup for every non-long-zero sender address with no cross-request caching. The gas throttle — the primary rate-control mechanism — is completely bypassed for these failing requests: requests with `gas ≤ 10,000` consume zero gas tokens, and even if gas is higher, the full amount is restored when the result is `null` (pre-EVM failure). The only remaining control is the global RPS cap (default 500/s), allowing an unauthenticated attacker to drive 500 uncached database alias lookups per second at zero gas cost.

### Finding Description

**Code path:**

`ContractController.call()` → `throttleManager.throttle(request)` → `contractExecutionService.processCall()` → `ContractCallContext.run()` → `doProcessCall()` → `transactionExecutionService.execute()` → `buildContractCallTransactionBody()` → `defaultTransactionBodyBuilder()` → `getSenderAccountID()` → `getSenderAccountIDAsNum()` → `aliasesReadableKVState.get(convertAddressToProtoBytes(senderAddress))` → `AliasesReadableKVState.readFromDataSource()` → `commonEntityAccessor.get(alias.value(), timestamp)` → **database query**.

**Root cause 1 — No cross-request cache:**

`ContractCallContext` is created fresh per request via `ScopedValue.where(SCOPED_VALUE, new ContractCallContext())`. Its `readCache` is a plain `HashMap` that is discarded after each request. `AliasedAccountCacheManager.putAccountNum()` writes only into this per-request cache. There is no shared, cross-request cache for alias-to-AccountID mappings. Every request with a unique non-existent address unconditionally hits the database. [1](#0-0) [2](#0-1) 

**Root cause 2 — Gas throttle is bypassed:**

`ThrottleProperties.scaleGas()` returns `0` for any `gas ≤ 10,000`. `gasLimitBucket.tryConsume(0)` always succeeds, consuming no tokens. [3](#0-2) 

Even for `gas > 10,000`, `restoreGasToBucket()` is called in the `finally` block of `doProcessCall()`. When the exception is thrown before EVM execution, `result` is `null`, so the full `gasLimitToRestoreBaseline` (100% of gas limit by default) is restored to the bucket — net gas cost is zero. [4](#0-3) [5](#0-4) 

**Root cause 3 — No per-IP limiting:**

The RPS bucket is a single global `Bucket` shared across all clients. There is no per-source-IP sub-limit. [6](#0-5) 

**Trigger point:** [7](#0-6) 

The alias lookup at line 271 hits the database for every non-long-zero address that is not already in the per-request cache. For a non-existent address, `readFromDataSource()` returns `null`, `throwPayerAccountNotFoundException()` is called, and the request terminates — but the DB query already executed. [8](#0-7) 

### Impact Explanation

At the default RPS cap of 500/s, an attacker sustains 500 uncached database queries per second at zero gas cost. Each query searches for a non-existent entity, producing a full-table or index scan miss. Sustained over time this elevates database CPU, I/O, and connection utilization. In deployments with small connection pools or shared database infrastructure (importer + web3 sharing the same PostgreSQL instance), this can degrade or deny service to legitimate users. The `requestsPerSecond` default of 500 is the sole remaining control. [9](#0-8) 

### Likelihood Explanation

No authentication, API key, or account is required. The attacker only needs to POST to `/api/v1/contracts/call` with a valid JSON body, a non-zero `from` address, and `gas ≤ 10,000`. Unique addresses are trivially generated (random 20-byte hex strings). The attack is repeatable indefinitely and requires no special tooling beyond a standard HTTP client capable of 500 req/s.

### Recommendation

1. **Add a cross-request negative cache** for alias lookups: cache `(address → NOT_FOUND)` results in a bounded, TTL-expiring shared cache (e.g., Caffeine) so repeated lookups for the same non-existent address do not hit the database.
2. **Do not restore gas for pre-EVM failures**: when `result == null` due to a pre-check failure (e.g., `PAYER_ACCOUNT_NOT_FOUND`), do not restore gas to the bucket. The gas was consumed as a cost of the lookup work performed.
3. **Add per-IP rate limiting** at the ingress layer (reverse proxy or Spring filter) to prevent a single client from consuming the full global RPS budget.
4. **Validate the `from` field** against known-existing addresses or require a minimum gas value that is meaningful to the gas throttle (`> 10,000`).

### Proof of Concept

```bash
# Generate unique random EVM addresses and send at max RPS
for i in $(seq 1 10000); do
  ADDR=$(python3 -c "import secrets; print('0x' + secrets.token_hex(20))")
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"from\":\"$ADDR\",\"to\":\"0x0000000000000000000000000000000000000167\",\"gas\":10000,\"data\":\"0x\"}" &
done
# Each request: passes RPS throttle, consumes 0 gas tokens,
# triggers one DB alias lookup for a non-existent address,
# fails with PAYER_ACCOUNT_NOT_FOUND, restores 0 gas tokens.
# Net effect: 500 DB queries/second sustained indefinitely.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L77-81)
```java
    @SneakyThrows
    public static <T> T run(Function<ContractCallContext, T> function) {
        return ScopedValue.where(SCOPED_VALUE, new ContractCallContext())
                .call(() -> function.apply(SCOPED_VALUE.get()));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/AliasedAccountCacheManager.java (L23-25)
```java
    public void putAccountNum(final AccountID accountID, final Account account) {
        getReadCache(AccountReadableKVState.STATE_ID).putIfAbsent(accountID, account);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L122-129)
```java
        } catch (MirrorEvmTransactionException e) {
            // This result is needed in case of exception to be still able to call restoreGasToBucket method
            result = e.getResult();
            status = e.getMessage();
            throw e;
        } finally {
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L140-152)
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
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L267-285)
```java
    private AccountID getSenderAccountIDAsNum(final Address senderAddress) {
        AccountID accountIDNum;
        if (senderAddress != null && !ConversionUtils.isLongZero(senderAddress)) {
            // If the address is an alias we need to first check if it exists and get the AccountID as a num.
            accountIDNum = aliasesReadableKVState.get(convertAddressToProtoBytes(senderAddress));
            if (accountIDNum == null) {
                throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
            }
        } else {
            final var senderAccountID = accountIdFromEvmAddress(senderAddress);
            // If the address was passed as a long-zero address we need to convert it to the correct AccountID type.
            accountIDNum = AccountID.newBuilder()
                    .accountNum(senderAccountID.getAccountNum())
                    .shardNum(senderAccountID.getShardNum())
                    .realmNum(senderAccountID.getRealmNum())
                    .build();
        }
        return accountIDNum;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AliasesReadableKVState.java (L57-68)
```java
    protected AccountID readFromDataSource(@NonNull ProtoBytes alias) {
        final var timestamp = ContractCallContext.get().getTimestamp();
        final var entity = commonEntityAccessor.get(alias.value(), timestamp);
        return entity.map(e -> {
                    final var account = accountFromEntity(e, timestamp);
                    final var accountID = account.accountId();
                    // Put the account in the account num cache.
                    aliasedAccountCacheManager.putAccountNum(accountID, account);
                    return accountID;
                })
                .orElse(null);
    }
```
