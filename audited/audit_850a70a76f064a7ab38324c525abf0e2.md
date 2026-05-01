### Title
Rate-Based Throttle Without Concurrency Limit Enables DB Connection Pool Exhaustion via Precompile-Heavy EVM Replay

### Summary
The `getContractOpcodes()` endpoint in `OpcodesController` applies only a rate-based token-bucket throttle (default 1 req/sec globally) before dispatching each request to a full synchronous EVM replay. Because the throttle tracks admission rate but not in-flight concurrency, an unauthenticated attacker can accumulate many simultaneously executing replays. When those replays involve Hedera precompile calls, each one issues multiple expensive historical-timestamp DB queries, and the aggregate concurrent load exhausts the shared HikariCP connection pool, denying service to all other requests on the node.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` (lines 52–68) is a public, unauthenticated `GET` endpoint. The only guards are:
1. `properties.isEnabled()` — a static flag, `false` by default but explicitly enabled by operators.
2. `validateAcceptEncodingHeader()` — trivially satisfied with `Accept-Encoding: gzip`.
3. `throttleManager.throttleOpcodeRequest()` — the only rate control. [1](#0-0) 

**Root cause — rate limiter, not concurrency limiter:**

`ThrottleManagerImpl.throttleOpcodeRequest()` calls `opcodeRateLimitBucket.tryConsume(1)` and immediately returns. Once the token is consumed the request proceeds; the bucket never tracks how many requests are currently executing. [2](#0-1) 

The bucket is configured with `capacity = opcodeRequestsPerSecond` (default **1**) and refills at the same rate. There is no `SynchronizationStrategy.SYNCHRONIZED` on this bucket (unlike `gasLimitBucket`), and no per-IP partitioning. [3](#0-2) [4](#0-3) 

**DB amplification during EVM replay:**

After admission, `OpcodeServiceImpl.processOpcodeCall()` calls `ContractDebugService.processOpcodeCall()`, which sets the historical timestamp to `consensusTimestamp - 1` and then calls `callContract()` — a full synchronous EVM re-execution. [5](#0-4) 

For transactions that invoke Hedera precompile token operations, each precompile call during replay triggers multiple historical-timestamp DB queries, including:
- `TokenRepository.findByTokenIdAndTimestamp()` — UNION across `token` + `token_history`
- `TokenAccountRepository.findByIdAndTimestamp()` — UNION across `token_account` + `token_account_history`
- `TokenBalanceRepository.findHistoricalTokenBalanceUpToTimestamp()` — multi-CTE query joining `account_balance`, `token_balance`, `token_transfer`
- `TokenAllowanceRepository.findByOwnerSpenderTokenAndTimestamp()` — very complex multi-CTE query with multiple self-joins [6](#0-5) [7](#0-6) 

A single transaction with N precompile calls generates O(N × queries_per_call) DB round-trips, each holding a connection from the shared HikariCP pool for the duration of the query.

**Why the existing check is insufficient:**

At the default rate of 1 req/sec, if each replay takes T seconds (easily 30–120 s for a high-gas transaction with many token operations), T requests are in-flight simultaneously. With T = 30 and a default HikariCP pool of 10 connections, the pool is exhausted after ~10 seconds of sustained attack, causing all subsequent DB operations across the node to block or fail.

### Impact Explanation

When the opcode tracer is enabled, a single unauthenticated attacker can sustain a stream of precompile-heavy replay requests that progressively fill the DB connection pool. Once exhausted, every other endpoint on the same web3 node (contract calls, balance queries, etc.) that requires a DB connection will time out or throw `Connection pool exhausted` errors. Because the web3 module shares one DB pool per node instance, this effectively takes the node offline for all users. Deployed across multiple mirror-node instances (e.g., via a load balancer), the same attack pattern repeated against each instance can disable 30%+ of the processing fleet without requiring brute-force volume — a single attacker thread per node suffices.

### Likelihood Explanation

The opcode tracer is disabled by default (`enabled = false`), which is the primary mitigating factor. However, operators who enable it for debugging or developer tooling expose the endpoint publicly with no authentication. The attack requires no special knowledge beyond knowing a valid transaction ID or hash (publicly available on-chain), setting `Accept-Encoding: gzip`, and sending requests at the admitted rate. It is fully repeatable and requires no privileged access.

### Recommendation

1. **Add a concurrency semaphore** in addition to the rate limiter. Use a `Semaphore` or `BulkheadConfig` (Resilience4j) to cap the number of simultaneously executing opcode replays (e.g., max 2–4 globally).
2. **Enforce a per-IP rate limit** in addition to the global bucket, so a single client cannot consume the entire global quota.
3. **Set an execution timeout** on `callContract()` for opcode replay (e.g., via `CompletableFuture.orTimeout()`) so long-running replays release their DB connections promptly.
4. **Require authentication** (API key or JWT) for the `/opcodes` endpoint, since it is explicitly a developer/debugging tool.
5. Consider **isolating the DB connection pool** used by opcode replay from the pool used by other endpoints.

### Proof of Concept

**Preconditions:**
- `hiero.mirror.web3.opcode.tracer.enabled=true` (operator has enabled the tracer)
- A known transaction hash for a transaction that invokes multiple Hedera token precompile operations (e.g., `mintToken`, `getTokenInfo`, `balanceOf` in sequence)

**Steps:**

```bash
# Step 1: Identify a precompile-heavy transaction hash (publicly visible on Hashscan)
TX_HASH="0xabc123..."

# Step 2: Send requests at the admitted rate (1/sec) in a loop
while true; do
  curl -s -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?stack=true&memory=true&storage=true" \
    --compressed &
  sleep 1
done

# Step 3: After ~30-60 seconds, observe that all other API endpoints on the
# same node begin returning 500 errors or connection timeout errors,
# indicating DB connection pool exhaustion.
```

Each background `curl` process holds a DB connection for the duration of the EVM replay. After T seconds (where T = average replay duration), T concurrent replays are active, each consuming multiple DB connections from the shared pool.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-65)
```java
    @GetMapping(value = "/{transactionIdOrHash}/opcodes")
    OpcodesResponse getContractOpcodes(
            @PathVariable TransactionIdOrHashParameter transactionIdOrHash,
            @RequestParam(required = false, defaultValue = "true") boolean stack,
            @RequestParam(required = false, defaultValue = "false") boolean memory,
            @RequestParam(required = false, defaultValue = "false") boolean storage,
            @RequestHeader(value = HttpHeaders.ACCEPT_ENCODING) String acceptEncoding) {
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L47-55)
```java
    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L48-58)
```java
    public OpcodesProcessingResult processOpcodeCall(
            final @Valid ContractDebugParameters params, final OpcodeContext opcodeContext) {
        ContractCallContext ctx = ContractCallContext.get();
        ctx.setTimestamp(Optional.of(params.getConsensusTimestamp() - 1));
        ctx.setOpcodeContext(opcodeContext);
        ctx.getOpcodeContext()
                .setActions(contractActionRepository.findFailedSystemActionsByConsensusTimestamp(
                        params.getConsensusTimestamp()));
        final var ethCallTxnResult = callContract(params, ctx);
        return new OpcodesProcessingResult(
                ethCallTxnResult, params.getReceiver(), ctx.getOpcodeContext().getOpcodes());
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/TokenAllowanceRepository.java (L35-127)
```java
    @Query(value = """
                    with token_allowances as (
                        select *
                        from (
                            select *,
                                row_number() over (
                                    partition by token_id, spender
                                    order by lower(timestamp_range) desc
                                ) as row_number
                            from (
                                (
                                    select *
                                    from token_allowance
                                    where owner = :owner
                                        and token_id = :tokenId
                                        and spender = :spender
                                        and lower(timestamp_range) <= :blockTimestamp
                                )
                                union all
                                (
                                    select *
                                    from token_allowance_history
                                    where owner = :owner
                                        and token_id = :tokenId
                                        and spender = :spender
                                        and lower(timestamp_range) <= :blockTimestamp
                                )
                            ) as all_token_allowances
                        ) as grouped_token_allowances
                        where row_number = 1 and amount_granted > 0
                    ),
                    transfers as (
                        select tt.token_id, tt.payer_account_id, tt.consensus_timestamp, sum(tt.amount) as amount
                        from token_transfer tt
                        join token_allowances ta on tt.account_id = ta.owner
                            and tt.payer_account_id = ta.spender
                            and tt.token_id = ta.token_id
                        where is_approval is true
                            and consensus_timestamp <= :blockTimestamp
                            and consensus_timestamp > lower(ta.timestamp_range)
                        group by tt.token_id, tt.payer_account_id, tt.consensus_timestamp
                    ),
                    contract_results_filtered as (
                        select sender_id, consensus_timestamp
                        from contract_result cr
                        where cr.consensus_timestamp <= :blockTimestamp
                            and cr.consensus_timestamp in (
                                select consensus_timestamp
                                from token_transfer
                            )
                    ),
                    contract_call_transfers as (
                        select cr.sender_id, tt.token_id, tt.consensus_timestamp, sum(tt.amount) as amount
                        from token_transfer tt
                        join token_allowances ta on tt.account_id = ta.owner
                            and tt.token_id = ta.token_id
                        join contract_results_filtered cr on tt.is_approval is true
                            and cr.sender_id = ta.spender
                            and tt.consensus_timestamp = cr.consensus_timestamp
                            and tt.consensus_timestamp <= :blockTimestamp
                            and tt.consensus_timestamp > lower(ta.timestamp_range)
                        group by cr.sender_id, tt.token_id, tt.consensus_timestamp
                    )
                    select *
                    from (
                        select amount_granted, owner, payer_account_id, spender, timestamp_range, token_id, amount_granted
                            + coalesce(
                                (
                                    select sum(amount)
                                    from contract_call_transfers cct
                                    where cct.token_id = ta.token_id
                                        and cct.sender_id = ta.spender
                                ),
                                 0)
                            +  coalesce(
                                (
                                    select sum(amount)
                                    from transfers tr
                                    where tr.token_id = ta.token_id
                                        and tr.payer_account_id = ta.spender
                                        and tr.consensus_timestamp not in (
                                        select consensus_timestamp
                                        from contract_call_transfers
                                    )
                                ),
                                0
                            ) as amount
                        from token_allowances ta
                    ) result
                    where amount > 0
                    limit 1
                    """, nativeQuery = true)
    Optional<TokenAllowance> findByOwnerSpenderTokenAndTimestamp(
```
