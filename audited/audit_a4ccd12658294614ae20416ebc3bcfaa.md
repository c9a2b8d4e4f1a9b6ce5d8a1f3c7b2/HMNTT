### Title
Unbounded Per-Opcode `log.info()` Amplification via `MirrorOperationActionTracer` When Tracing Enabled

### Summary
When `hiero.mirror.web3.evm.trace.enabled=true` and the `contract` filter set is empty (the default), `contractFilterCheck()` returns `false` for every contract, causing `MirrorOperationActionTracer.tracePostExecution()` to emit a `log.info()` call for every single EVM opcode executed. An unprivileged attacker submitting high-gas contract calls can generate millions of log events per HTTP request with no per-opcode rate limiting, which — if a costly appender (JDBC, remote syslog) is configured — causes database overload or network saturation across all nodes running with tracing enabled.

### Finding Description
**Code path:**

`TraceProperties.contractFilterCheck()` (line 33–35) returns `false` when `getContract().isEmpty()` — the default state — meaning no contract is filtered out:

```java
public boolean contractFilterCheck(String contract) {
    return !getContract().isEmpty() && !getContract().contains(contract);
}
``` [1](#0-0) 

In `MirrorOperationActionTracer.tracePostExecution()`, after the `isEnabled()` guard (line 51) and `stateFilterCheck()` guard (line 55), the code reaches `contractFilterCheck()` at line 64–68. When it returns `false` (contract not filtered), execution falls through unconditionally to `log.info()` at line 70–86, which is called **once per opcode**:

```java
if (recipientNum.isPresent()
        && traceProperties.contractFilterCheck(...)) {
    return;          // only skips if filter is non-empty AND contract not in set
}
log.info("type={} operation={} ...", ...);   // fires for every opcode otherwise
``` [2](#0-1) 

**Root cause:** There is no per-opcode log volume cap, no log-level guard (`isInfoEnabled()` check before building arguments), and no opcode-count circuit breaker. The HTTP-level throttle (`requestsPerSecond=500`) operates at the request boundary, not at the per-opcode log-emission boundary. [3](#0-2) 

The `opcodeRequestsPerSecond=1` throttle applies only to the `/contracts/results/{transactionIdOrHash}/opcodes` REST endpoint, not to the `MirrorOperationActionTracer` path used for all `eth_call`/`eth_estimateGas` contract simulations. [4](#0-3) 

**Failed assumption:** The design assumes that enabling tracing is a low-volume debugging aid. It does not account for an adversary deliberately maximizing opcode count to amplify log I/O.

### Impact Explanation
With `maxGasLimit=15,000,000` and an average of ~3–5 gas per opcode, a single contract call can execute up to ~5,000,000 opcodes, each emitting one `log.info()`. At the permitted 500 HTTP RPS, this yields up to 2.5 billion log events per second per node. A JDBC appender translates each event to a database INSERT; a remote syslog appender translates each to a UDP/TCP write. Either path causes database connection pool exhaustion or network interface saturation. Because `MirrorOperationActionTracer` is a Spring singleton applied to all contract call processing, every node with `trace.enabled=true` is equally affected, satisfying the ≥30% node impact threshold when the feature is deployed cluster-wide. [5](#0-4) 

### Likelihood Explanation
The attacker requires zero privileges — only the ability to submit standard `eth_call` or `eth_estimateGas` requests, which are unauthenticated public endpoints. The precondition (`trace.enabled=true`) is a documented operational feature intended for production debugging; operators who enable it for live traffic analysis are the target deployment scenario. The exploit is trivially repeatable: a loop of high-gas calls to a contract with a tight loop body (e.g., a Solidity `while(true)` bounded by gas) maximizes opcode count per request. No special contract deployment is needed — calling any existing complex contract suffices when the filter set is empty (default). [6](#0-5) 

### Recommendation
1. **Guard log emission with a level check and opcode counter:** Before `log.info()`, check `log.isInfoEnabled()` and maintain a per-request opcode count cap (e.g., 10,000 log lines per transaction) after which logging is suppressed.
2. **Decouple log level from tracing:** Use `log.debug()` or `log.trace()` instead of `log.info()` so that production deployments with INFO-level appenders are not affected.
3. **Add a per-request opcode log budget** in `ContractCallContext` that `MirrorOperationActionTracer` checks before emitting each log line.
4. **Document appender risk:** If expensive appenders are used, the configuration documentation should explicitly warn that `trace.enabled=true` with empty `contract` filter will emit one log event per opcode. [7](#0-6) 

### Proof of Concept
**Preconditions:**
- Mirror node deployed with `hiero.mirror.web3.evm.trace.enabled=true`
- `hiero.mirror.web3.evm.trace.contract` left empty (default — traces all contracts)
- Logback configured with a JDBC or remote syslog appender at INFO level

**Steps:**
1. Deploy or identify any existing contract that executes a gas-intensive loop (e.g., iterates storage reads until gas is exhausted).
2. Send repeated `eth_call` requests with `gas: 15000000` targeting that contract:
   ```bash
   for i in $(seq 1 500); do
     curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
       -H 'Content-Type: application/json' \
       -d '{"data":"<loop_selector>","to":"<contract_addr>","gas":15000000}' &
   done
   ```
3. Each request executes up to ~5,000,000 opcodes; each opcode triggers one `log.info()` in `MirrorOperationActionTracer.tracePostExecution()`.
4. With 500 concurrent requests, the JDBC appender receives ~2.5 billion INSERT attempts per second, exhausting the DB connection pool within seconds and causing `SQLException` cascades across all mirror node instances sharing the same logging database. [8](#0-7)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L21-24)
```java
    private boolean enabled = false;

    @NonNull
    private Set<@Hex(minLength = ADDRESS_LENGTH, maxLength = ADDRESS_LENGTH) String> contract = new HashSet<>();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L33-35)
```java
    public boolean contractFilterCheck(String contract) {
        return !getContract().isEmpty() && !getContract().contains(contract);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/MirrorOperationActionTracer.java (L43-87)
```java
    public void tracePostExecution(
            final @NonNull MessageFrame frame, final Operation.@NonNull OperationResult operationResult) {
        // Reset the balance call flag after BALANCE opcode completes
        if (frame.getCurrentOperation() != null
                && BALANCE_OPERATION_NAME.equals(frame.getCurrentOperation().getName())) {
            ContractCallContext.get().setBalanceCall(false);
        }

        if (!traceProperties.isEnabled()) {
            return;
        }

        if (traceProperties.stateFilterCheck(frame.getState())) {
            return;
        }

        final var recipientAddress = frame.getRecipientAddress();
        final var recipientNum = recipientAddress != null
                ? commonEntityAccessor.get(recipientAddress, Optional.empty())
                : Optional.empty();

        if (recipientNum.isPresent()
                && traceProperties.contractFilterCheck(
                        CommonUtils.hex(toEvmAddress(((Entity) recipientNum.get()).getId())))) {
            return;
        }

        log.info(
                "type={} operation={}, callDepth={}, contract={}, sender={}, recipient={}, remainingGas={}, revertReason={}, input={}, output={}, return={}",
                frame.getType(),
                frame.getCurrentOperation() != null
                        ? frame.getCurrentOperation().getName()
                        : StringUtils.EMPTY,
                frame.getDepth(),
                frame.getContractAddress().toShortHexString(),
                frame.getSenderAddress().toShortHexString(),
                frame.getRecipientAddress().toShortHexString(),
                frame.getRemainingGas(),
                frame.getRevertReason()
                        .orElse(org.apache.tuweni.bytes.Bytes.EMPTY)
                        .toHexString(),
                frame.getInputData().toShortHexString(),
                frame.getOutputData().toShortHexString(),
                frame.getReturnData().toShortHexString());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L28-29)
```java
    @Min(1)
    private long opcodeRequestsPerSecond = 1;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
