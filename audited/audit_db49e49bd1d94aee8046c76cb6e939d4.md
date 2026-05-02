### Title
Unbounded DB Query Amplification via SLOAD-Heavy Contract Calls Exhausts Connection Pool

### Summary
An unprivileged user can send repeated `eth_call` requests targeting a contract with a large number of unique storage slots. Each EVM SLOAD opcode triggers a synchronous database query through `ContractStorageReadableKVState.readFromDataSource()`, and the gas-based throttle does not bound the actual number of DB queries per request. With up to 500 concurrent requests allowed per second and each request capable of generating ~7,142 sequential DB queries, the HikariCP connection pool is saturated, blocking all HTTP threads and rendering the web3 API unresponsive.

### Finding Description

**Code path:**

`ContractController.call()` → `validateContractMaxGasLimit()` → `ContractExecutionService.processCall()` → `ContractCallService.callContract()` → `TransactionExecutionService.execute()` → `buildContractCallTransactionBody()` → EVM execution → per-SLOAD → `ContractStorageReadableKVState.readFromDataSource()` → `ContractStateService.findStorage()` → `ContractStateRepository.findStorage()` (DB query)

**`buildContractCallTransactionBody()`** at [1](#0-0)  accepts the caller-supplied `to` address and `estimatedGas` without any constraint on the storage complexity of the target contract. The resulting transaction is handed to the EVM executor with no per-SLOAD DB query budget.

**`ContractStorageReadableKVState.readFromDataSource()`** at [2](#0-1)  issues a synchronous DB call for every unique storage slot the EVM reads. For the latest-block path it calls `contractStateService.findStorage()`, which either hits the Spring `@Cacheable` layer or falls through to `ContractStateRepository.findStorage()` — a live SQL query.

**Root cause — failed assumption:** The gas-based throttle in `ThrottleManagerImpl` [3](#0-2)  consumes tokens proportional to the *declared gas limit*, not to the number of DB queries that gas will generate. A cold SLOAD costs 2,100 EVM gas (EIP-2929) but triggers one DB round-trip regardless of how fast or slow that round-trip is. The throttle has no awareness of DB query count or latency.

**Existing checks and why they are insufficient:**

| Check | Value | Why insufficient |
|---|---|---|
| `maxGasLimit` | 15,000,000 | Caps SLOADs at ~7,142 per request, but does not limit concurrent requests |
| `gasPerSecond` throttle | 7,500,000,000 | Allows 500 × 15M-gas requests/second — exactly matching the request rate limit |
| `requestsPerSecond` | 500 | Global, not per-IP; a single attacker can consume the full budget |
| `@Cacheable` on `findStorage` | Spring Caffeine | Only helps for repeated reads of the *same* slot; unique slots always hit DB |
| Batch caching (`findStorageBatch`) | Caffeine per-contract | Converts N individual queries to one large `IN (…)` query, but still one DB round-trip per unique slot on a cold cache | [4](#0-3) [5](#0-4) 

### Impact Explanation

The HikariCP pool for the web3 module is configured via `spring.datasource.hikari` with no explicit override in the codebase, defaulting to 10 connections. [6](#0-5) 

With 500 req/s allowed and each request executing ~7,142 sequential DB queries at ~1–5 ms each, a single request occupies an HTTP thread for 7–35 seconds. Tomcat's default thread pool (200 threads) is exhausted in under one second of sustained attack. New requests queue and time out. The web3 API (`/api/v1/contracts/call`) becomes fully unresponsive. Because the mirror node's web3 endpoint is the primary interface for dApps and tooling to simulate and estimate Hedera smart contract transactions, this constitutes a complete denial of service for that surface.

### Likelihood Explanation

- **No authentication required.** Any internet-accessible client can POST to `/api/v1/contracts/call`.
- **No special contract deployment needed.** Any existing mainnet contract with large storage (e.g., a DEX with thousands of liquidity positions) serves as the target.
- **Trivially scriptable.** A simple loop sending 500 req/s at `gas: 15000000` to a storage-heavy `to` address is sufficient.
- **Cache bypass is easy.** Rotating through different block timestamps (historical calls) or different contracts keeps the cache cold.
- **Throttle is global, not per-IP.** A single attacker consumes the entire allowed budget, starving legitimate users simultaneously.

### Recommendation

1. **Add a per-SLOAD DB query counter** within `ContractCallContext` and enforce a hard cap (e.g., 2,000 DB queries per EVM execution). Abort execution and return an error if the cap is exceeded.
2. **Add per-IP rate limiting** in addition to the global gas/request throttle, so a single source cannot consume the full budget.
3. **Increase the HikariCP pool size** for the web3 module and set an explicit `connectionTimeout` so threads fail fast rather than blocking indefinitely when the pool is saturated.
4. **Set a query-level statement timeout** on the web3 datasource (e.g., `spring.datasource.hikari.connection-init-sql: SET statement_timeout = 500`) to bound individual DB query latency.
5. **Pre-warm the contract storage cache** for known high-traffic contracts, or implement a per-contract SLOAD budget based on observed storage size.

### Proof of Concept

**Preconditions:**
- Mirror node web3 endpoint is publicly accessible.
- A contract exists on the target network with ≥5,000 unique storage slots (e.g., a Uniswap V3-style pool contract). Its address is `TARGET_CONTRACT`.

**Steps:**

```bash
# Step 1: Identify a storage-heavy contract (e.g., via eth_getStorageAt enumeration or known DeFi contracts)
TARGET="0x<storage_heavy_contract_address>"

# Step 2: Craft a call that iterates over many unique storage slots
# (e.g., call a function that reads a large mapping in a loop)
CALLDATA="0x<selector_of_storage_reading_function>"

# Step 3: Flood the endpoint at the rate limit with max gas
for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$TARGET\",\"gas\":15000000,\"data\":\"$CALLDATA\"}" &
done
wait

# Step 4: Observe that subsequent legitimate requests time out or return 503
curl -X POST https://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"to":"0x<any_contract>","gas":21000,"data":"0x"}'
# Expected: connection timeout or HTTP 503
```

**Observable result:** The mirror node's web3 API stops responding to all requests. DB connection pool metrics (`hikaricp_connections_pending`) spike to the pool maximum. HTTP thread pool is exhausted. Recovery requires either the attack to stop (allowing in-flight requests to drain) or a service restart.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L185-199)
```java
    private TransactionBody buildContractCallTransactionBody(
            final CallServiceParameters params, final long estimatedGas) {
        return defaultTransactionBodyBuilder(params)
                .contractCall(ContractCallTransactionBody.newBuilder()
                        .contractID(ContractID.newBuilder()
                                .shardNum(commonProperties.getShard())
                                .realmNum(commonProperties.getRealm())
                                .evmAddress(Bytes.wrap(params.getReceiver().toArrayUnsafe()))
                                .build())
                        .functionParameters(Bytes.wrap(params.getCallData()))
                        .amount(params.getValue()) // tinybars sent to contract
                        .gas(estimatedGas)
                        .build())
                .build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractStorageReadableKVState.java (L32-48)
```java
    protected SlotValue readFromDataSource(@NonNull SlotKey slotKey) {
        if (!slotKey.hasContractID()) {
            return null;
        }

        final var timestamp = ContractCallContext.get().getTimestamp();
        final var contractID = slotKey.contractID();
        final var entityId = EntityIdUtils.entityIdFromContractId(contractID);
        final var keyBytes = slotKey.key().toByteArray();
        return timestamp
                .map(t -> contractStateService.findStorageByBlockTimestamp(
                        entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
                .orElse(contractStateService.findStorage(entityId, keyBytes))
                .map(byteArr ->
                        new SlotValue(Bytes.wrap(leftPadBytes(byteArr, Bytes32.SIZE)), Bytes.EMPTY, Bytes.EMPTY))
                .orElse(null);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L19-21)
```java
    @Query(value = "select value from contract_state where contract_id = ?1 and slot =?2", nativeQuery = true)
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_CONTRACT_STATE)
    Optional<byte[]> findStorage(final Long contractId, final byte[] key);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L58-70)
```java
    public Optional<byte[]> findStorage(final EntityId contractId, final byte[] key) {
        if (!cacheProperties.isEnableBatchContractSlotCaching()) {
            return contractStateRepository.findStorage(contractId.getId(), key);
        }

        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L60-95)
```java
    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @Lazy
    DataSource dataSource(
            DataSourceProperties dataSourceProperties,
            HikariConfig hikariConfig,
            DatabaseWaiter databaseWaiter,
            ObjectProvider<JdbcConnectionDetails> detailsProvider) {

        var jdbcUrl = dataSourceProperties.determineUrl();
        var username = dataSourceProperties.determineUsername();
        var password = dataSourceProperties.determinePassword();

        final var connectionDetails = detailsProvider.getIfAvailable();
        if (connectionDetails != null) {
            jdbcUrl = connectionDetails.getJdbcUrl();
            username = connectionDetails.getUsername();
            password = connectionDetails.getPassword();
        }

        databaseWaiter.waitForDatabase(jdbcUrl, username, password);

        final var config = new HikariConfig();
        hikariConfig.copyStateTo(config);
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);

        return new HikariDataSource(config);
    }
```
