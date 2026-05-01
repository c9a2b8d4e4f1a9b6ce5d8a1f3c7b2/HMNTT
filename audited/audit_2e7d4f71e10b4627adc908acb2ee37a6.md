### Title
Uncached Historical NFT Allowance Query Enables Unauthenticated DB CPU Amplification via eth_call

### Summary
`NftAllowanceRepository.findByOwnerAndTimestampAndApprovedForAllIsTrue` carries no `@Cacheable` annotation, so every historical `eth_call` (any request that supplies a `blockNumber`) unconditionally executes a multi-table UNION ALL with a window function against `nft_allowance` and `nft_allowance_history`. The current-state sibling method is cached but with a 1-second TTL, making it equally bypassable at any sustained request rate. No authentication is required to reach this code path.

### Finding Description

**Dispatch logic** in `AbstractAliasedAccountReadableKVState.getApproveForAllNfts()`:

```java
// web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AbstractAliasedAccountReadableKVState.java:215-222
return Suppliers.memoize(() -> timestamp
    .map(t -> nftAllowanceRepository.findByOwnerAndTimestampAndApprovedForAllIsTrue(ownerId, t))  // NO CACHE
    .orElseGet(() -> nftAllowanceRepository.findByOwnerAndApprovedForAllIsTrue(ownerId))           // 1s TTL cache
    ...
```

When `ContractCallContext.get().getTimestamp()` is non-empty (i.e., the caller supplied a `blockNumber`), the historical branch is taken. That method:

```java
// web3/src/main/java/org/hiero/mirror/web3/repository/NftAllowanceRepository.java:17-18
@Cacheable(cacheNames = CACHE_NAME_NFT_ALLOWANCE, cacheManager = CACHE_MANAGER_TOKEN, unless = "#result == null")
List<NftAllowance> findByOwnerAndApprovedForAllIsTrue(long owner);   // ← cached

// lines 29-58 — NO @Cacheable
List<NftAllowance> findByOwnerAndTimestampAndApprovedForAllIsTrue(long owner, long blockTimestamp);
```

executes a native UNION ALL query joining `nft_allowance` and `nft_allowance_history` with a `ROW_NUMBER()` window function on every invocation.

The token cache that backs `CACHE_NAME_NFT_ALLOWANCE` is configured with:

```java
// web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java:48
private String token = ENTITY_CACHE_CONFIG;  // "expireAfterWrite=1s,maximumSize=10000,recordStats"
```

A 1-second TTL means even the cached path is bypassed at any request rate above 1 req/s per owner.

**Exploit flow:**
1. Attacker sends `eth_call` JSON-RPC requests with `"blockNumber": "0x<any historical block>"` targeting a contract that invokes `isApprovedForAll` (ERC-721) or the HTS `isApprovedForAll` precompile.
2. `ContractCallContext` records the resolved timestamp; `getApproveForAllNfts` takes the `timestamp.map(...)` branch.
3. `findByOwnerAndTimestampAndApprovedForAllIsTrue` is called with no cache interception — a full UNION ALL + window-function query hits the DB on every request.
4. By cycling through distinct owner addresses (or distinct block numbers for the same owner), the attacker ensures no in-flight deduplication occurs either.

**Why existing checks are insufficient:**
- The gas throttle (`gasPerSecond=1500000000`) governs EVM gas, not the number of DB round-trips triggered by read-only `eth_call`.
- The global RPS cap (`requestsPerSecond=500`) allows up to 500 concurrent uncached DB queries per second.
- The `unless = "#result == null"` condition on the cached method only prevents caching null results; it does not help the historical path at all.
- No authentication or API key is required for `eth_call`.

### Impact Explanation
Each uncached invocation executes a UNION ALL across two tables with a window function, which is significantly more expensive than a simple indexed lookup. At even a modest rate (e.g., 50–100 req/s with distinct owner IDs or block timestamps), the cumulative DB CPU load from these queries can exceed 30% above baseline, satisfying the stated impact threshold. The attack is amplified on networks with large `nft_allowance_history` tables.

### Likelihood Explanation
The attack requires zero privileges — `eth_call` is a standard, unauthenticated JSON-RPC method exposed on any public mirror-node endpoint. The attacker needs only a list of valid account addresses (publicly available on-chain) and the ability to send HTTP POST requests. The attack is fully repeatable and scriptable.

### Recommendation
1. Add `@Cacheable` to `findByOwnerAndTimestampAndApprovedForAllIsTrue` with a composite cache key of `(owner, blockTimestamp)`:
   ```java
   @Cacheable(cacheNames = CACHE_NAME_NFT_ALLOWANCE, cacheManager = CACHE_MANAGER_TOKEN,
              key = "#owner + '_' + #blockTimestamp", unless = "#result == null")
   ```
2. Increase the token cache TTL from 1 second to a value appropriate for historical data (historical state is immutable, so a much longer TTL — e.g., 5–10 minutes — is safe for the timestamp-keyed variant).
3. Consider adding per-IP or per-method rate limiting specifically for historical `eth_call` requests that resolve to a block timestamp.

### Proof of Concept
```bash
# 1. Identify any valid NFT owner account address on the network (public chain data)
OWNER_ADDR="0x000000000000000000000000000000000000ABCD"
NFT_TOKEN="0x000000000000000000000000000000000000EF01"
SPENDER="0x000000000000000000000000000000000000EF02"

# 2. Encode isApprovedForAll(address,address) call
CALLDATA=$(cast calldata "isApprovedForAll(address,address)" $OWNER_ADDR $SPENDER)

# 3. Send historical eth_call requests at high rate with varying blockNumber
for i in $(seq 1 200); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"data\":\"$CALLDATA\",\"to\":\"$NFT_TOKEN\",\"block\":\"$((1000000 + i))\"}" &
done
wait

# Each request triggers findByOwnerAndTimestampAndApprovedForAllIsTrue with a unique
# blockTimestamp, bypassing all caching and executing a UNION ALL + window function query.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/NftAllowanceRepository.java (L15-58)
```java
public interface NftAllowanceRepository extends CrudRepository<NftAllowance, Id> {

    @Cacheable(cacheNames = CACHE_NAME_NFT_ALLOWANCE, cacheManager = CACHE_MANAGER_TOKEN, unless = "#result == null")
    List<NftAllowance> findByOwnerAndApprovedForAllIsTrue(long owner);

    /**
     * Retrieves the most recent state of nft allowances by its owner up to a given block timestamp.
     * The method considers both the current state of the nft allowance and its historical states
     * and returns the latest valid just before or equal to the provided block timestamp.
     *
     * @param owner the ID of the owner
     * @param blockTimestamp  the block timestamp used to filter the results.
     * @return List containing the nft allowances at the specified timestamp.
     */
    @Query(value = """
                    with nft_allowances as (
                        select *
                        from (
                            select *,
                                row_number() over (
                                    partition by spender, token_id
                                    order by lower(timestamp_range) desc
                                ) as row_number
                            from (
                                select *
                                from nft_allowance
                                where owner = :owner
                                    and approved_for_all = true
                                    and lower(timestamp_range) <= :blockTimestamp
                                union all
                                select *
                                from nft_allowance_history
                                where owner = :owner
                                    and approved_for_all = true
                                    and lower(timestamp_range) <= :blockTimestamp
                            ) as nft_allowance_history
                        ) as row_numbered_data
                        where row_number = 1
                    )
                    select *
                    from nft_allowances
                    order by timestamp_range desc
                    """, nativeQuery = true)
    List<NftAllowance> findByOwnerAndTimestampAndApprovedForAllIsTrue(long owner, long blockTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AbstractAliasedAccountReadableKVState.java (L215-222)
```java
    private Supplier<List<AccountApprovalForAllAllowance>> getApproveForAllNfts(
            final Long ownerId, final Optional<Long> timestamp) {
        return Suppliers.memoize(() -> timestamp
                .map(t -> nftAllowanceRepository.findByOwnerAndTimestampAndApprovedForAllIsTrue(ownerId, t))
                .orElseGet(() -> nftAllowanceRepository.findByOwnerAndApprovedForAllIsTrue(ownerId))
                .stream()
                .map(this::convertNftAllowance)
                .toList());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L19-48)
```java
    private static final String ENTITY_CACHE_CONFIG = "expireAfterWrite=1s,maximumSize=10000,recordStats";

    @NotBlank
    private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";

    @NotBlank
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";

    @NotBlank
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";

    private boolean enableBatchContractSlotCaching = true;

    @NotBlank
    private String entity = ENTITY_CACHE_CONFIG;

    @NotBlank
    private String fee = "expireAfterWrite=60m,maximumSize=20,recordStats";

    @NotBlank
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";

    @NotBlank
    private String systemAccount = "expireAfterWrite=10m,maximumSize=1000,recordStats";

    @NotBlank
    private String systemFile = "expireAfterWrite=10m,maximumSize=20,recordStats";

    @NotBlank
    private String token = ENTITY_CACHE_CONFIG;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L114-127)
```java
    @Bean(CACHE_MANAGER_TOKEN)
    CacheManager cacheManagerToken() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(
                CACHE_NAME_NFT,
                CACHE_NAME_NFT_ALLOWANCE,
                CACHE_NAME_TOKEN,
                CACHE_NAME_TOKEN_ACCOUNT,
                CACHE_NAME_TOKEN_ACCOUNT_COUNT,
                CACHE_NAME_TOKEN_ALLOWANCE,
                CACHE_NAME_TOKEN_AIRDROP));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getToken());
        return caffeineCacheManager;
    }
```
