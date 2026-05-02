Now I have all the information needed. Let me analyze the full call chain.

### Title
Uncaught `UnsupportedOperationException` from `FeeEstimationFeeContext.readableStore()` Propagates as HTTP 500 on `POST /api/v1/network/fees?mode=STATE`

### Summary
`FeeEstimationFeeContext.readableStore()` throws `UnsupportedOperationException` for any store interface not in its explicit allow-list. Neither `FeeEstimationService.estimateFees()` nor `NetworkController.estimateFees()` catch `UnsupportedOperationException`, so any unprivileged user who POSTs a transaction type whose congestion-multiplier logic requests an unhandled store in STATE mode receives an HTTP 500 instead of a fee estimate. The codebase's own test suite explicitly acknowledges this escape path with a TODO noting the upstream fix is pending.

### Finding Description

**Exact code path:**

1. `NetworkController.estimateFees()` receives a POST with `mode=STATE`: [1](#0-0) 

   The only caught exception is `ParseException`. `UnsupportedOperationException` is not caught here.

2. `FeeEstimationService.estimateFees()` builds a `FeeEstimationFeeContext` and calls `calculator.calculateTxFee()`: [2](#0-1) 

   Catch blocks cover only `ParseException`, `NullPointerException`, and `IllegalStateException`. `UnsupportedOperationException` is not caught.

3. During fee calculation in STATE mode, the upstream `UtilizationScaledThrottleMultiplier` (CN library) calls `readableStore()` on the `FeeEstimationFeeContext`. For store interfaces not in the explicit allow-list, the method unconditionally throws: [3](#0-2) 

   The handled stores are: `ReadableTopicStore`, `ReadableTokenStore`, `ReadableAccountStore`, `ContractStateStore`, `ReadableFileStore`, `ReadableNftStore`, `ReadableTokenRelationStore`. Any other store type triggers the throw.

4. The TODO comment at line 64–65 explicitly acknowledges this is a known, unfixed gap pending an upstream CN fix: [4](#0-3) 

5. The test suite confirms `UnsupportedOperationException` escapes `estimateFees()` at the service level for certain transaction types in STATE mode, and catches it only in the test — not in production code: [5](#0-4) 

**Root cause:** The `readableStore()` allow-list is incomplete relative to the set of stores the upstream CN fee/congestion-multiplier logic may request. The exception thrown for unrecognized stores is `UnsupportedOperationException`, which is a `RuntimeException` subclass not caught anywhere in the controller-to-service call chain.

### Impact Explanation
Any transaction type whose STATE-mode congestion multiplier requests a store not in the allow-list causes the fee estimation endpoint to return HTTP 500 for all callers using that transaction type with `mode=STATE`. This disrupts fee estimation for smart contract and other operations, degrading service reliability. No funds are directly at risk, but the endpoint becomes unreliable for affected transaction types, which is consistent with the stated medium severity (layer 0/1/2 network code, unintended behavior, no direct fund loss).

### Likelihood Explanation
No authentication or privilege is required. The endpoint is publicly accessible (`POST /api/v1/network/fees?mode=STATE`). An attacker only needs to identify a transaction type that triggers the unhandled store — the test suite at line 386–417 iterates all known transaction types and explicitly tolerates this failure, confirming at least some types are affected. The attack is trivially repeatable with a single HTTP request.

### Recommendation
Add a catch for `UnsupportedOperationException` in `FeeEstimationService.estimateFees()` and translate it to a well-defined client or server error (e.g., `IllegalArgumentException` with a descriptive message, or a dedicated `UnsupportedTransactionTypeException` mapped to HTTP 400/422). Alternatively, fix the root cause by either expanding the `readableStore()` allow-list to cover all stores the CN congestion-multiplier may request, or — per the existing TODO — coordinate with the upstream CN team to null-check stores in `UtilizationScaledThrottleMultiplier` so it never calls `readableStore()` for stores the mirror node cannot provide.

### Proof of Concept
1. Identify a transaction type whose STATE-mode fee calculation requests a store not in the allow-list (the test at `FeeEstimationServiceTest.java:386–417` iterates all types; any that throws `UnsupportedOperationException` with "Store not supported:" is a candidate).
2. Serialize that transaction as a protobuf `Transaction` message.
3. Send:
   ```
   POST /api/v1/network/fees?mode=STATE
   Content-Type: application/protobuf
   <serialized transaction bytes>
   ```
4. Observe HTTP 500 response instead of a fee estimate. The exception propagates uncaught from `FeeEstimationFeeContext.readableStore()` → `FeeEstimationService.estimateFees()` → `NetworkController.estimateFees()` → Spring's default error handler → HTTP 500.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L118-124)
```java
        try {
            final var transaction = Transaction.PROTOBUF.parse(Bytes.wrap(body));
            return toResponse(feeEstimationService.estimateFees(transaction, mode, highVolumeThrottle));
        } catch (ParseException e) {
            throw new IllegalArgumentException("Unable to parse transaction", e);
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationService.java (L99-116)
```java
        try {
            final var txContext = new TransactionFeeContext(transaction);
            final var context = mode == FeeEstimateMode.STATE
                    ? txContext.withFeeContext(newFeeContext(txContext.body(), throttleUtilization))
                    : txContext;
            final SimpleFeeCalculator calculator = Objects.requireNonNull(feeManager.getSimpleFeeCalculator());
            return calculator.calculateTxFee(context.body(), context);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Unable to parse transaction", e);
        } catch (NullPointerException e) {
            throw new IllegalArgumentException("Unknown transaction type", e);
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof UnknownHederaFunctionality) {
                throw new IllegalArgumentException("Unknown transaction type", e);
            }
            throw e;
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationFeeContext.java (L64-65)
```java
    // Congestion multiplier reads these in STATE mode; return 0 so multiplier stays at 1x.
    // TODO: remove once CN fixes standalone executor to use null congestionMultipliers.
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationFeeContext.java (L195-218)
```java
    public <T> T readableStore(@NonNull final Class<T> storeInterface) {
        if (storeInterface == ReadableTopicStore.class) {
            return (T) topicStore;
        }
        if (storeInterface == ReadableTokenStore.class) {
            return (T) tokenStore;
        }
        if (storeInterface == ReadableAccountStore.class) {
            return (T) EMPTY_ACCOUNT_STORE;
        }
        if (storeInterface == ContractStateStore.class) {
            return (T) EMPTY_CONTRACT_STATE_STORE;
        }
        if (storeInterface == ReadableFileStore.class) {
            return (T) EMPTY_FILE_STORE;
        }
        if (storeInterface == ReadableNftStore.class) {
            return (T) EMPTY_NFT_STORE;
        }
        if (storeInterface == ReadableTokenRelationStore.class) {
            return (T) EMPTY_TOKEN_RELATION_STORE;
        }
        throw new UnsupportedOperationException("Store not supported: " + storeInterface.getSimpleName());
    }
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/service/fee/FeeEstimationServiceTest.java (L404-416)
```java
            // STATE mode may additionally throw for types whose congestion multiplier reads stores
            // not backed by mirror state (accounts, contracts, files, NFTs, token relations).
            // Pending upstream fix in CN's UtilizationScaledThrottleMultiplier to null-check stores.
            try {
                assertThat(service.estimateFees(txn, FeeEstimateMode.STATE, 0).totalTinycents())
                        .as("STATE fee for %s", type)
                        .isGreaterThanOrEqualTo(0);
            } catch (UnsupportedOperationException e) {
                assertThat(e).hasMessageContaining("Store not supported:");
            } catch (IllegalArgumentException e) {
                assertThat(e).hasMessageContaining("Unknown transaction type");
            }
        }
```
