### Title
Opcode Replay Throttle Bypasses Gas-Based Cost Accounting, Enabling Resource Exhaustion via Maximum-Gas Transaction Replays

### Summary
`ThrottleManagerImpl.throttleOpcodeRequest()` enforces only a flat count-based rate limit (default: 1 RPS) and never consumes from the `gasLimitBucket`, which is the mechanism that protects the system from computationally expensive EVM executions. An unprivileged attacker can repeatedly request opcode traces for historical transactions that consumed maximum gas (up to 15,000,000 gas), each of which triggers a full EVM replay with per-opcode stack/memory/storage capture, exhausting CPU and memory resources far beyond what the throttle was designed to handle.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` calls `throttleManager.throttleOpcodeRequest()` at line 61 before dispatching to `opcodeService.processOpcodeCall()`. [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` (lines 52–56) only consumes 1 token from `opcodeRateLimitBucket`: [2](#0-1) 

By contrast, the regular `throttle()` method for contract calls consumes from **both** `rateLimitBucket` (count) and `gasLimitBucket` (gas amount proportional to the request's declared gas): [3](#0-2) 

**Root cause:** `throttleOpcodeRequest()` never touches `gasLimitBucket`. The gas-based throttle — the only mechanism that accounts for computational cost — is completely absent for opcode requests. The throttle treats a 21,000-gas replay identically to a 15,000,000-gas replay.

**Failed assumption:** The design assumes 1 RPS is a safe ceiling. This is only true if all replayed transactions have similar computational cost. In reality, the gas cost of the replayed transaction is determined by the historical transaction's actual execution, which can be up to `maxGasLimit` (15,000,000 gas per configuration): [4](#0-3) 

**Exploit flow:**
1. Attacker identifies (or previously submitted) a historical transaction that consumed maximum gas (e.g., a complex DeFi contract call at 15M gas).
2. Attacker sends `GET /api/v1/contracts/results/{txHash}/opcodes?stack=true&memory=true&storage=true` with `Accept-Encoding: gzip`.
3. `throttleOpcodeRequest()` consumes 1 token — passes immediately.
4. `OpcodeServiceImpl.processOpcodeCall()` triggers a full EVM replay via `contractDebugService.processOpcodeCall()`, capturing stack, memory, and storage state at every single opcode step across 15M gas worth of execution.
5. The `gasLimitBucket` is never touched, so the gas-based protection never fires.
6. At 1 RPS, the attacker queues up expensive replays faster than the server can complete them (a 15M-gas replay with full tracing can take many seconds), causing thread pool exhaustion and OOM.

**Why existing checks are insufficient:**

- The `opcodeRateLimitBucket` (1 RPS default) only counts requests, not their cost: [5](#0-4) 
- The `gasLimitBucket` (7.5B gas/s default) is never consulted for opcode requests: [2](#0-1) 
- The `requestTimeout` of 10,000ms does not prevent the EVM replay work from consuming CPU/memory before the timeout fires: [6](#0-5) 
- The gzip header requirement (`validateAcceptEncodingHeader`) only reduces response bandwidth, not server-side computation: [7](#0-6) 

### Impact Explanation

Each opcode request for a maximum-gas transaction triggers a full EVM re-execution with per-opcode state capture. The `OpcodeContext` is initialized with `(int) params.getGas() / 3` as the initial opcode list capacity: [8](#0-7) 

For a 15M gas transaction, this pre-allocates ~5M opcode slots. With `stack=true`, `memory=true`, `storage=true`, each slot captures the full EVM frame state. At 1 RPS, if each replay takes >1 second (which is expected for maximum-gas transactions with full tracing), requests queue up, exhausting the web3 service's thread pool and heap. This degrades or halts the mirror node's ability to serve all endpoints, including transaction confirmation queries.

### Likelihood Explanation

- No authentication or authorization is required; the endpoint is publicly accessible to any user.
- The attacker only needs to know one historical transaction hash for a high-gas transaction — these are publicly visible on any Hedera block explorer.
- The attack is trivially repeatable with a single `curl` command in a loop.
- The attacker does not need to submit new transactions; they can reuse the same maximum-gas transaction hash indefinitely.
- Even at the default 1 RPS, if each replay takes 5–30 seconds, the attack is effective.

### Recommendation

1. **Consume from `gasLimitBucket` in `throttleOpcodeRequest()`**: Look up the gas used by the historical transaction from the `ContractResult` record before executing the replay, and consume that amount from `gasLimitBucket` — mirroring the behavior of `throttle()` for regular calls.
2. **Alternatively, enforce a gas ceiling per opcode request**: Reject opcode requests for transactions whose recorded `gasUsed` exceeds a configurable threshold (e.g., `maxOpcodeReplayGas`).
3. **Apply the `restore()` mechanism**: After the replay completes, restore unused gas back to the bucket (as `ContractCallService.restoreGasToBucket()` does for regular calls): [9](#0-8) 

### Proof of Concept

```bash
# Step 1: Find a historical high-gas transaction hash from a public explorer
TX_HASH="0x<high_gas_tx_hash>"

# Step 2: Send opcode trace requests at 1 RPS (the throttle limit)
# Each request triggers a full EVM replay of a 15M-gas transaction
while true; do
  curl -s -H "Accept-Encoding: gzip" \
    "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?stack=true&memory=true&storage=true" \
    -o /dev/null &
  sleep 1
done

# Result: Server CPU and heap are consumed by concurrent maximum-gas EVM replays.
# The gasLimitBucket is never decremented, so the gas-based throttle never fires.
# Thread pool exhaustion causes all mirror node endpoints to become unresponsive.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-64)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L75-86)
```java
    private void validateAcceptEncodingHeader(String acceptEncodingHeader) {
        if (acceptEncodingHeader == null || !acceptEncodingHeader.toLowerCase().contains("gzip")) {
            throw HttpClientErrorException.create(
                    MISSING_GZIP_HEADER_MESSAGE,
                    HttpStatus.NOT_ACCEPTABLE,
                    HttpStatus.NOT_ACCEPTABLE.getReasonPhrase(),
                    null, // headers
                    null, // body
                    null // charset
                    );
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
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

**File:** docs/configuration.md (L707-707)
```markdown
| `hiero.mirror.web3.evm.maxGasLimit`                          | 15000000                                           | The maximum amount of gas limit the user can supply in the request.                                                                                                                              |
```

**File:** docs/configuration.md (L717-717)
```markdown
| `hiero.mirror.web3.requestTimeout`                           | 10000                                              | The maximum amount of time to wait for a request to process.                                                                                                                                     |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L67-67)
```java
            final var opcodeContext = new OpcodeContext(opcodeRequest, (int) params.getGas() / 3);
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
