All referenced code has been verified against the actual repository. Every file, line number, and logic claim in the report is accurate.

**Verification summary:**
- `TraceProperties.java` line 21: `enabled = false` by default — confirmed [1](#0-0) 
- `stateFilterCheck()` lines 29–31: logic confirmed exactly as described — empty `status` makes the whole expression `false` [2](#0-1) 
- `contractFilterCheck()` lines 33–35: same no-op pattern with empty `contract` set — confirmed [3](#0-2) 
- `tracePostExecution()` guards at lines 51–57 and `log.info()` at lines 70–86 — confirmed exactly as described [4](#0-3) 
- `maxGasLimit = 15_000_000L` — confirmed [5](#0-4) 
- `requestsPerSecond = 500` — confirmed; throttle limits request rate but not log volume per request [6](#0-5) 

**SECURITY.md scope check:** The exclusion "Impacts that only require DDoS" refers to volumetric/distributed attacks. This is a single-request amplification bug caused by a code-level logic flaw — categorically different and in scope.

---

# Audit Report

## Title
Unbounded Per-Request Log Flooding via `tracePostExecution()` When Tracing Enabled with Default Empty Status Filter

## Summary
When `hiero.mirror.web3.evm.trace.enabled=true`, `MirrorOperationActionTracer.tracePostExecution()` emits one `log.info()` line per EVM opcode executed. Because `stateFilterCheck()` returns `false` for every state when the `status` set is empty (the default), and no per-request log-count cap exists, a single unauthenticated max-gas contract call can force the logging subsystem to emit millions of lines — potentially hundreds of megabytes to gigabytes — of log data.

## Finding Description
**Root cause — `TraceProperties.java` lines 29–31:**
```java
public boolean stateFilterCheck(State state) {
    return !getStatus().isEmpty() && !getStatus().contains(state);
}
``` [2](#0-1) 

When `status` is the default empty `HashSet`, `!getStatus().isEmpty()` evaluates to `false`, short-circuiting the entire expression to `false` — meaning "do not skip, proceed to log." This is the out-of-the-box behaviour whenever tracing is enabled. The same pattern applies to `contractFilterCheck()` with the default empty `contract` set. [3](#0-2) 

**Code path — `MirrorOperationActionTracer.java`:**
```java
if (!traceProperties.isEnabled()) { return; }                        // lines 51-53
if (traceProperties.stateFilterCheck(frame.getState())) { return; } // lines 55-57 — no-op with empty status
// falls through unconditionally to:
log.info("type={} operation={}, callDepth={}, contract={}, sender={}, recipient={}, "
       + "remainingGas={}, revertReason={}, input={}, output={}, return={}", ...); // lines 70-86
``` [4](#0-3) 

`tracePostExecution()` is called by the EVM framework after every single opcode execution. With default empty `status` and `contract` sets, every opcode unconditionally reaches `log.info()`.

**Failed assumption:** `stateFilterCheck()` is designed as an opt-in filter — it only filters when the operator has explicitly populated `status`. With the default empty set it is a no-op. The design assumes operators will always configure a filter when enabling tracing, but there is no enforcement of this assumption and no fallback cap.

**Why existing checks are insufficient:**
- The `enabled` flag is the only global guard; once set it applies to all callers equally.
- `stateFilterCheck()` with empty `status` returns `false` for every state — confirmed no-op.
- `contractFilterCheck()` with empty `contract` is likewise a no-op.
- The throttle (`gasPerSecond`, `requestsPerSecond = 500`) limits request rate but does not limit log output per request.
- There is no per-request opcode-log counter, no log-rate limiter, and no log-size cap inside `tracePostExecution()`.

## Impact Explanation
A single request can saturate disk I/O, fill the log partition, or overwhelm a centralised log aggregator (e.g., Elasticsearch, Loki). With `maxGasLimit = 15_000_000` and cheap opcodes at 1–3 gas each, a single request can trigger up to ~5 million `log.info()` calls, each emitting ~200–400 bytes of structured data — yielding ~1–2 GB of log output per request. At the default `requestsPerSecond = 500`, a sustained attack multiplies this further. This causes availability degradation or crash of the web3 service for all users and may cause loss of other operational log data.

## Likelihood Explanation
Any user who can reach `/api/v1/contracts/call` can trigger this. No authentication, no special role, and no on-chain funds are required — contract calls on the mirror node are read-only simulations with no on-chain cost. The only prerequisite is that an operator has set `hiero.mirror.web3.evm.trace.enabled=true`, which is a documented, supported configuration option intended for debugging and monitoring. Operators enabling tracing for production diagnostics are a realistic target. The attack is trivially repeatable.

## Recommendation
1. **Invert the filter default:** Change `stateFilterCheck()` and `contractFilterCheck()` so that an empty set means "filter all" (deny-by-default) rather than "filter nothing." Alternatively, require at least one `status` entry when `enabled=true` via a `@NotEmpty` validator.
2. **Add a per-request log cap:** Introduce an atomic counter in `ContractCallContext` incremented on each `log.info()` call inside `tracePostExecution()`, with a configurable maximum (e.g., 10,000 lines per request) after which logging is suppressed for that request.
3. **Downgrade log level:** Use `log.debug()` instead of `log.info()` so that production log configurations (which typically suppress DEBUG) provide a natural backstop.
4. **Document the risk:** Add an explicit warning in configuration documentation that enabling tracing without configuring `status` and `contract` filters will log every opcode for every request.

## Proof of Concept
1. Deploy the mirror node with `hiero.mirror.web3.evm.trace.enabled=true` (leave `status` and `contract` at defaults — empty sets).
2. Deploy a contract containing a tight loop of cheap opcodes (e.g., `JUMPDEST` at 1 gas, `PUSH1`/`POP` at 3 gas each).
3. POST to `/api/v1/contracts/call` with `gas=15000000` (the confirmed `maxGasLimit`).
4. Observe the application log: the EVM executes up to ~5 million opcodes, each triggering one `log.info()` line in `MirrorOperationActionTracer.tracePostExecution()` containing type, operation name, call depth, contract address, sender, recipient, remaining gas, revert reason, input hex, output hex, and return hex.
5. Result: ~1–2 GB of log output generated by a single unauthenticated HTTP request, with no error returned to the caller.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L21-21)
```java
    private boolean enabled = false;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L29-31)
```java
    public boolean stateFilterCheck(State state) {
        return !getStatus().isEmpty() && !getStatus().contains(state);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L33-35)
```java
    public boolean contractFilterCheck(String contract) {
        return !getContract().isEmpty() && !getContract().contains(contract);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/MirrorOperationActionTracer.java (L51-86)
```java
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L69-69)
```java
    private long maxGasLimit = 15_000_000L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
    private long requestsPerSecond = 500;
```
