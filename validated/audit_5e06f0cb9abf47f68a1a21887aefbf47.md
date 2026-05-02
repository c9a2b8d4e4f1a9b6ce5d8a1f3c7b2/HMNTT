All code references have been verified against the actual repository. Here is the analysis:

**Verified facts:**
- `ContractRepository.findRuntimeBytecode()` uses `unless = "#result == null"` — confirmed at line 16. `Optional.empty()` is non-null, so it is stored in the Caffeine cache.
- Cache spec is `expireAfterAccess=1h,maximumSize=1000,recordStats` — confirmed in `CacheProperties.java` line 22.
- `ContractBytecodeReadableKVState.readFromDataSource()` calls `.orElse(null)` on the cached `Optional.empty()`, returning `null` to the EVM — confirmed at lines 42–46.
- `ReadableKVStateBase.get()` uses a **per-request** `ContractCallContext` (Java `ScopedValue`) as its read cache, so it calls `readFromDataSource()` on every new request, hitting the shared Caffeine cache each time — confirmed in `ReadableKVStateBase.java` lines 60–70 and `ContractCallContext.java` lines 25, 78–81.
- The `POST /api/v1/contracts/call` endpoint is unauthenticated — confirmed in `ContractController.java`.
- `ContractRepositoryTest.findRuntimeBytecodeFailCall()` confirms querying a non-existent ID returns `Optional.empty()` (which gets cached per the `unless` condition).

---

## Audit Report

## Title
Cache Poisoning via `Optional.empty()` Caching in `ContractRepository.findRuntimeBytecode()` Causes Newly Deployed Contracts to Appear Non-Existent for Up to 1 Hour

## Summary
The `@Cacheable` annotation on `findRuntimeBytecode()` uses `unless = "#result == null"` as its cache exclusion condition. Because `Optional.empty()` is a non-null singleton object, Spring stores it in the shared Caffeine cache. An unprivileged attacker who queries a not-yet-deployed contract ID via the public `POST /api/v1/contracts/call` endpoint poisons the cache with `Optional.empty()`. All subsequent EVM bytecode lookups for that contract ID return the cached empty result for up to 1 hour, making a newly deployed contract appear non-existent to the mirror node's EVM.

## Finding Description

**Root cause — incorrect `unless` condition:** [1](#0-0) 

The method returns `Optional<byte[]>`. When no contract exists, the DB returns no rows and Spring Data JPA wraps that as `Optional.empty()`. Spring evaluates `#result == null` against the actual return value; `Optional.empty()` is not `null`, so the condition is `false` and the empty `Optional` **is stored in the cache**.

**Cache configuration — 1-hour shared Caffeine cache:** [2](#0-1) 

This is a singleton Spring bean, shared across all requests.

**Consumer — `ContractBytecodeReadableKVState.readFromDataSource()`:** [3](#0-2) 

When the Caffeine cache returns `Optional.empty()`, `.orElse(null)` returns `null`, and the EVM treats the contract as having no bytecode.

**Per-request cache does not protect against this:** `ReadableKVStateBase.get()` uses a `ContractCallContext` backed by Java `ScopedValue` as its read cache. Each new HTTP request creates a fresh `ContractCallContext`, so `hasBeenRead()` is always `false` at the start of each request, and `readFromDataSource()` is called, which hits the shared Caffeine cache. [4](#0-3) [5](#0-4) 

**No timestamp awareness in `ContractBytecodeReadableKVState`:** Unlike `TokenReadableKVState`, which branches on `ContractCallContext.get().getTimestamp()` for historical vs. latest queries, `ContractBytecodeReadableKVState.readFromDataSource()` has no such branching and always uses the same Caffeine cache key (`contractId` Long). [6](#0-5) 

**Public unauthenticated entry point:** [7](#0-6) 

**Test confirms the behavior:** `findRuntimeBytecodeFailCall` queries a non-existent ID and receives `Optional.empty()`, which is cached per the `unless` condition. `findRuntimeBytecodeSuccessfulCall` confirms the cache persists across DB deletions for positive results, demonstrating the cache is durable. [8](#0-7) 

## Impact Explanation
Any user or dApp relying on the mirror node's `/api/v1/contracts/call` endpoint to interact with a newly deployed contract will receive incorrect results for up to 1 hour:
- All `eth_call` simulations against the new contract return as if the contract has no code.
- All gas estimations for calls to the new contract fail or return incorrect values.
- Any dApp using the mirror node as its EVM simulation backend immediately after contract deployment is broken for the cache TTL window.

## Likelihood Explanation
Hedera entity IDs are strictly sequential and publicly observable in real time via the mirror node's own REST API (`/api/v1/contracts`, `/api/v1/accounts`). Predicting the next contract entity ID requires only a single read of the current maximum ID. The attack requires no credentials, no tokens, and no special network access — only the ability to send HTTP POST requests to the public endpoint. The attacker can spray a range of predicted IDs (e.g., the next 100 sequential IDs) at negligible cost, since the cache holds up to 1000 entries. The attack is repeatable and can be automated.

## Recommendation
Fix the `unless` SpEL expression to also exclude empty `Optional` results from being cached:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

This ensures that only successful (non-empty) bytecode lookups are stored in the long-lived Caffeine cache, while absent-contract results always fall through to the database on each request. [1](#0-0) 

## Proof of Concept

1. Observe the current highest contract entity ID on Hedera via `GET /api/v1/contracts?order=desc&limit=1`. Suppose the highest ID is `N`.
2. Send `POST /api/v1/contracts/call` with `"to": "0x000000000000000000000000000000000000<N+1>"` (long-zero EVM address of entity `N+1`). The EVM calls `ContractBytecodeReadableKVState.readFromDataSource()` → `findRuntimeBytecode(N+1)` → DB returns no rows → `Optional.empty()` → stored in Caffeine cache under key `N+1`.
3. A legitimate user deploys a contract; it receives entity ID `N+1` and its bytecode is written to the DB.
4. Any subsequent `POST /api/v1/contracts/call` targeting contract `N+1` hits the Caffeine cache, receives `Optional.empty()`, and the EVM returns as if the contract has no code — calls revert or return empty results.
5. This persists for up to 1 hour (`expireAfterAccess=1h`) or until the entry is evicted by LRU pressure from 1000 other entries.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java (L16-18)
```java
    @Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
    @Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
    Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L22-22)
```java
    private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L39-47)
```java
    protected Bytecode readFromDataSource(@NonNull ContractID contractID) {
        final var entityId = toEntityId(contractID);

        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
    }
```

**File:** web3/src/main/java/com/swirlds/state/spi/ReadableKVStateBase.java (L60-70)
```java
    public V get(@NonNull K key) {
        // We need to cache the item because somebody may perform business logic basic on this
        // contains call, even if they never need the value itself!
        Objects.requireNonNull(key);
        if (!hasBeenRead(key)) {
            final var value = readFromDataSource(key);
            markRead(key, value);
        }
        final var value = getReadCache().get(key);
        return (value == marker) ? null : (V) value;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L78-81)
```java
    public static <T> T run(Function<ContractCallContext, T> function) {
        return ScopedValue.where(SCOPED_VALUE, new ContractCallContext())
                .call(() -> function.apply(SCOPED_VALUE.get()));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/TokenReadableKVState.java (L73-83)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
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

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/ContractRepositoryTest.java (L33-38)
```java
    @Test
    void findRuntimeBytecodeFailCall() {
        Contract contract = domainBuilder.contract().persist();
        long id = contract.getId();
        assertThat(contractRepository.findRuntimeBytecode(++id)).isEmpty();
    }
```
