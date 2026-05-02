### Title
Log Amplification Griefing via `contractFilterCheck()` Empty-Set Default When Tracing Is Enabled

### Summary
When `hiero.mirror.web3.evm.trace.enabled=true` is set by an operator and the `contract` filter set remains at its default empty state, `contractFilterCheck()` returns `false` for every contract address, causing `MirrorOperationActionTracer.tracePostExecution()` to emit a `log.info()` entry for every single EVM opcode executed. Any unprivileged external user can deliberately submit high-gas contract calls to amplify log volume proportionally to opcode count and call depth, with no per-user log-rate limiting in place.

### Finding Description

**Exact code path:**

`TraceProperties.java` lines 33–35:
```java
public boolean contractFilterCheck(String contract) {
    return !getContract().isEmpty() && !getContract().contains(contract);
}
```
When `getContract()` is empty (the default — `new HashSet<>()`), the expression short-circuits to `false`, meaning "do not filter out this contract." Every contract address passes.

`MirrorOperationActionTracer.java` lines 51–86 — `tracePostExecution()` logic:
1. Line 51: if `!traceProperties.isEnabled()` → return (only guard against tracing being off)
2. Line 55: `stateFilterCheck` — skips if state set is non-empty and state doesn't match
3. Lines 64–68: `contractFilterCheck` — skips only if contract set is non-empty AND contract is absent
4. Lines 70–86: **`log.info(...)` fires unconditionally** — one entry per opcode execution, including `callDepth`, `remainingGas`, `input`, `output`, `return`, `revertReason`

**Root cause:** The empty-set sentinel meaning "match all" is a correct design for opt-in filtering, but it creates an unbounded log sink when `enabled=true`. There is no log-rate limiter, no per-user quota, and no cap on log entries per request.

**Failed assumption:** The design assumes that operators who enable tracing with an empty filter accept full-volume tracing. It does not account for adversarial users deliberately maximizing opcode count to amplify that volume.

### Impact Explanation

- `maxGasLimit` is 15,000,000 gas (`EvmProperties.java` line 65). A tight-loop contract can execute tens of thousands of opcodes within that budget.
- `requestsPerSecond` default is 500 (`ThrottleProperties.java` line 35). At 500 RPS × ~10,000 opcodes/call = **5,000,000 `log.info()` entries per second**, each containing frame metadata (addresses, gas, input/output hex strings).
- This can cause: log storage exhaustion, disk I/O saturation on the mirror node host, log-shipping pipeline overload (e.g., Elasticsearch/Loki), and JVM GC pressure from string formatting at high throughput.
- Severity is Medium (griefing, no economic damage to network users, but availability impact on the mirror node operator's infrastructure).

### Likelihood Explanation

- **Precondition:** Operator must have set `enabled=true`. This is a realistic operational scenario (debugging, monitoring, incident investigation).
- **Attacker capability:** Zero — any user with access to the `eth_call` or `/api/v1/contracts/call` endpoint can submit contract calls. No authentication required.
- **Repeatability:** Fully repeatable and scriptable. Attacker deploys a loop contract once, then hammers the endpoint at the RPS limit.
- **Detection difficulty:** The attack is indistinguishable from legitimate high-gas contract calls; the log flood is a side-effect of normal tracing behavior.

### Recommendation

1. **Add a per-request log-entry cap:** Introduce a `maxLogEntriesPerRequest` property in `TraceProperties`. In `tracePostExecution()`, track a per-request counter (via `ContractCallContext`) and stop emitting after the cap is reached.
2. **Add a log-rate limiter:** Apply a token-bucket rate limiter (already used elsewhere via `ThrottleProperties`) specifically to trace log emissions, independent of the RPS throttle.
3. **Warn on dangerous configuration:** At startup, if `enabled=true` and `contract` set is empty, emit a warning that all contracts will be traced with no volume cap.
4. **Consider making the empty-set default opt-out instead of opt-in:** Require explicit `contract=*` wildcard rather than treating empty as "all," so operators must consciously choose unbounded tracing.

### Proof of Concept

**Preconditions:**
- Mirror node running with `hiero.mirror.web3.evm.trace.enabled=true`
- `hiero.mirror.web3.evm.trace.contract` left at default `[]`

**Steps:**

1. Deploy a gas-burning loop contract on the target network:
```solidity
contract GasBurner {
    function burn() external {
        uint256 i = 0;
        while (gasleft() > 5000) { unchecked { i++; } }
    }
}
```

2. Submit repeated calls at the RPS limit:
```bash
for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"<burn() selector>","to":"<contract_addr>","gas":15000000}' &
done
wait
```

3. **Observed result:** The mirror node's log output receives millions of `log.info` lines per second of the form:
```
type=MESSAGE_CALL operation=ADD, callDepth=0, contract=0x..., sender=0x..., recipient=0x..., remainingGas=14999xxx, ...
```
Log storage fills rapidly; log-shipping infrastructure is overwhelmed; mirror node JVM heap pressure increases from string allocation in the logging path.