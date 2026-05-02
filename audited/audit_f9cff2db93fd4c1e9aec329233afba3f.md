### Title
Missing Gas-Proportional Throttling in Opcode Replay Endpoint Enables Computational DoS

### Summary
`throttleOpcodeRequest()` only enforces a flat request-count limit via `opcodeRateLimitBucket`, while the analogous `throttle()` for regular contract calls additionally enforces a gas-proportional limit via `gasLimitBucket`. An unprivileged attacker can continuously replay the most gas-heavy historical transactions with full stack/memory/storage tracing at the maximum allowed rate (default 1 req/sec), accumulating concurrent expensive EVM re-executions that exhaust CPU and memory without any gas-cost-proportional back-pressure.

### Finding Description

**Code locations:**

`ThrottleManagerImpl.java:52-56` — `throttleOpcodeRequest()` consumes exactly 1 token from `opcodeRateLimitBucket` regardless of the gas cost of the transaction being replayed: [1](#0-0) 

`ThrottleManagerImpl.java:37-48` — `throttle()` for regular calls additionally consumes `scaleGas(request.getGas())` tokens from `gasLimitBucket`, providing gas-proportional back-pressure: [2](#0-1) 

`OpcodesController.java:61` — the controller calls only `throttleOpcodeRequest()`, bypassing the gas bucket entirely: [3](#0-2) 

`ThrottleProperties.java:29` — the default `opcodeRequestsPerSecond = 1` is a global (not per-IP) bucket: [4](#0-3) 

`ThrottleConfiguration.java:47-55` — `opcodeRateLimitBucket` is a single shared bean with no per-client partitioning: [5](#0-4) 

**Root cause:** The failed assumption is that a flat 1-request-per-second limit is sufficient to bound computational cost for the opcode endpoint. It is not, because the cost of replaying a 15M-gas transaction with full stack+memory+storage tracing is orders of magnitude higher than replaying a 21K-gas transaction, yet both consume exactly 1 token.

**Exploit flow:**

The `opcodeRateLimitBucket` refills at 1 token/second. An attacker sends exactly 1 request per second, each targeting the highest-gas historical transaction available, with `stack=true&memory=true&storage=true`. Each such replay triggers `contractDebugService.processOpcodeCall()` → `callContract()` → full EVM re-execution with per-opcode tracing: [6](#0-5) 

If each replay takes T seconds (e.g., 30s for a 15M-gas transaction with full tracing), after T seconds there are T concurrent replays running. The throttle check happens only at request admission time — there is no in-flight concurrency cap or gas-weighted admission control.

**Why existing checks are insufficient:**

- `opcodeRateLimitBucket` is count-only and global — one attacker monopolizes the entire budget.
- `gasLimitBucket` is never consulted for opcode requests, so the gas-proportional protection that guards `/api/v1/contracts/call` is entirely absent here.
- `restoreGasToBucket()` is called by `ContractCallService.doProcessCall()` after execution, but this only affects `gasLimitBucket`, which was never debited for opcode requests in the first place — it provides no back-pressure. [7](#0-6) 

### Impact Explanation

An attacker can cause sustained CPU and memory exhaustion on the mirror node web3 service by continuously triggering the most expensive possible EVM re-executions. Each replay with full opcode tracing allocates per-opcode stack/memory/storage snapshots in the `OpcodeContext`, which for a 15M-gas transaction can be gigabytes of heap. Accumulating even a handful of concurrent such replays can trigger OOM or saturate all available CPU cores, degrading or denying service for all other endpoints. The "corruption of in-flight replays" framing in the question is not supported — each replay runs in an isolated `ContractCallContext` — but the resource exhaustion DoS is concrete and severe. [8](#0-7) 

### Likelihood Explanation

**Preconditions:**
1. The operator must have set `hiero.mirror.web3.opcode.tracer.enabled=true` (default is `false`). [9](#0-8) 
2. The attacker needs to know the hash or transaction ID of a high-gas historical transaction — this is public information on any Hedera network.
3. No authentication, no API key, no privileged access required.

**Feasibility:** Once the endpoint is enabled, the attack is trivially repeatable with a simple script sending one HTTP GET per second. The attacker does not need to craft any special payload — they simply reference existing high-gas transactions from the public ledger. The global (non-per-IP) nature of the bucket means a single client can fully occupy the endpoint.

### Recommendation

1. **Add gas-proportional admission control to `throttleOpcodeRequest()`**: Before admitting the replay, look up the gas limit of the target transaction and consume proportional tokens from `gasLimitBucket` (or a dedicated opcode gas bucket), mirroring the logic in `throttle()`.
2. **Add a concurrency cap**: Reject new opcode requests if more than N replays are already in flight (e.g., via a `Semaphore`).
3. **Add per-IP rate limiting**: The current global bucket allows a single client to monopolize the endpoint. Use a per-source-IP bucket or require an authenticated API key.
4. **Cap replay gas**: Reject opcode requests for transactions whose gas limit exceeds a configurable maximum (e.g., 5M gas) to bound worst-case replay cost.

### Proof of Concept

```bash
# 1. Find the hash of a high-gas historical transaction from the public mirror REST API
TX_HASH=$(curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/contracts/results?limit=1&order=desc" \
  | jq -r '.results[0].hash')

# 2. Continuously replay it at 1 req/sec (matching the bucket refill rate),
#    with full tracing enabled, targeting the opcode endpoint
while true; do
  curl -s -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?stack=true&memory=true&storage=true" \
    --output /dev/null &
  sleep 1
done

# Each background job triggers a full EVM re-execution with per-opcode tracing.
# After ~30 seconds (if each replay takes ~30s), 30 concurrent replays are running,
# exhausting heap and CPU on the mirror node web3 service.
```

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L29-29)
```java
    private long opcodeRequestsPerSecond = 1;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L48-59)
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
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L109-137)
```java
    protected final EvmTransactionResult doProcessCall(
            CallServiceParameters params, long estimatedGas, boolean estimate) throws MirrorEvmTransactionException {
        EvmTransactionResult result = null;
        var status = ResponseCodeEnum.SUCCESS.toString();

        try {
            result = transactionExecutionService.execute(params, estimatedGas);

            if (!estimate) {
                validateResult(result, params);
            }
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw new MirrorEvmTransactionException(e.getMessage(), EMPTY);
        } catch (MirrorEvmTransactionException e) {
            // This result is needed in case of exception to be still able to call restoreGasToBucket method
            result = e.getResult();
            status = e.getMessage();
            throw e;
        } finally {
            if (!estimate) {
                restoreGasToBucket(result, params.getGas());

                // Only record metric if EVM is invoked and not inside estimate loop
                if (result != null) {
                    updateMetrics(params, result.gasUsed(), 1, status);
                }
            }
        }
        return result;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L64-74)
```java
    public OpcodesResponse processOpcodeCall(@NonNull OpcodeRequest opcodeRequest) {
        return ContractCallContext.run(ctx -> {
            final var params = buildCallServiceParameters(opcodeRequest.getTransactionIdOrHashParameter());
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);

            ctx.setOpcodeContext(opcodeContext);

            final OpcodesProcessingResult result = contractDebugService.processOpcodeCall(params, opcodeContext);
            return buildOpcodesResponse(result);
        });
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L11-11)
```java
    private boolean enabled = false;
```
