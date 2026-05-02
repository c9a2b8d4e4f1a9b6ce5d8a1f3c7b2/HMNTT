### Title
Contract Filter Bypass in `tracePostExecution` for Non-Existent Recipient Addresses Enables Log Flooding

### Summary
In `MirrorOperationActionTracer.tracePostExecution()`, the contract address filter (`contractFilterCheck()`) is only evaluated when `commonEntityAccessor.get()` returns a non-empty `Optional`. When a call targets a non-existent address, the lookup returns `Optional.empty()`, the filter is skipped entirely, and `log.info` fires unconditionally for every opcode in that call frame. An unprivileged user can exploit this to bypass an operator-configured contract filter and flood the node's logs.

### Finding Description
**Exact code location:** `web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/MirrorOperationActionTracer.java`, lines 59–86.

**Root cause:** The guard at lines 64–68 is:
```java
if (recipientNum.isPresent()
        && traceProperties.contractFilterCheck(...)) {
    return;
}
```
`contractFilterCheck()` is only invoked when `recipientNum.isPresent()` is `true`. When `commonEntityAccessor.get(recipientAddress, Optional.empty())` returns `Optional.empty()` — which happens for any address not registered in the mirror node's entity store — the short-circuit `&&` means `contractFilterCheck()` is never called. Execution falls through to `log.info` at line 70.

**`contractFilterCheck()` logic** (`TraceProperties.java`, lines 33–35):
```java
public boolean contractFilterCheck(String contract) {
    return !getContract().isEmpty() && !getContract().contains(contract);
}
```
When the `contract` set is non-empty (operator has restricted tracing to specific contracts), this returns `true` for unlisted contracts, causing a `return` (filter out). But this is never reached for non-existent recipients.

**Exploit flow:**
1. Operator enables tracing: `hiero.mirror.web3.evm.trace.enabled=true` and sets `hiero.mirror.web3.evm.trace.contract` to a non-empty set of specific contract addresses (intending to restrict log output).
2. Attacker submits a `eth_call` or contract transaction that executes a `CALL` opcode targeting any address not present in the entity store (e.g., a freshly generated random EVM address).
3. The EVM creates a sub-frame with that address as the recipient. For each opcode executed in that frame, `tracePostExecution` is invoked.
4. `commonEntityAccessor.get(recipientAddress, Optional.empty())` returns `Optional.empty()`.
5. The `contractFilterCheck()` branch is skipped; `log.info` fires for every opcode in the frame.
6. Attacker repeats across many transactions or within a loop in a single contract call.

**Why existing checks are insufficient:**
- The `isEnabled()` check (line 51) is a necessary precondition but is operator-controlled and set to `true` in diagnostic deployments.
- The `stateFilterCheck()` (line 55) filters by frame state, not by recipient — it does not protect against this bypass.
- There is no null/empty guard on `recipientNum` that would cause a safe default of "filter out" rather than "log unconditionally."

### Impact Explanation
When tracing is enabled with a contract filter, the operator's intent is to restrict log output to specific contracts. This bypass causes `log.info` to fire for every opcode in every call frame targeting a non-existent address, regardless of the filter. An attacker can generate unbounded INFO-level log entries, consuming disk I/O, storage, and log-aggregation pipeline capacity. This is a griefing attack with no direct economic damage to network users, matching the stated Medium scope.

### Likelihood Explanation
Any unprivileged user with access to the `eth_call` or contract execution endpoint can trigger this. The only precondition outside the attacker's control is that the operator has enabled tracing with a non-empty contract filter — a configuration used in production diagnostic and debugging scenarios. The attack requires no special knowledge beyond the public API and is trivially repeatable in a loop.

### Recommendation
Change the filter logic so that a missing recipient entity defaults to **filtering out** (not logging), rather than bypassing the filter. Replace lines 64–68 with:

```java
// If a contract filter is configured, only log for known, matching recipients
if (!traceProperties.getContract().isEmpty()) {
    if (recipientNum.isEmpty()) {
        return; // unknown recipient — filter out
    }
    if (traceProperties.contractFilterCheck(
            CommonUtils.hex(toEvmAddress(((Entity) recipientNum.get()).getId())))) {
        return;
    }
}
```

This ensures that when a contract filter is active, calls to non-existent addresses are silently dropped rather than unconditionally logged.

### Proof of Concept
1. Start the mirror node with:
   ```
   hiero.mirror.web3.evm.trace.enabled=true
   hiero.mirror.web3.evm.trace.contract=0x000000000000000000000000000000000000abcd
   ```
2. Deploy a contract `Flooder` with a function that calls a non-existent address in a loop:
   ```solidity
   function flood(uint n) external {
       address target = address(0xDEAD); // not in entity store
       for (uint i = 0; i < n; i++) {
           (bool ok,) = target.call("");
           // ok will be false; ignored
       }
   }
   ```
3. Call `flood(1000)` via `eth_call`.
4. Observe that the mirror node emits `log.info` entries for opcodes in each sub-frame targeting `0xDEAD`, despite `0xDEAD` not being in the configured contract filter set.
5. The configured filter address `0xabcd` is never logged (correctly filtered), but `0xDEAD` bypasses the filter entirely. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/MirrorOperationActionTracer.java (L59-68)
```java
        final var recipientAddress = frame.getRecipientAddress();
        final var recipientNum = recipientAddress != null
                ? commonEntityAccessor.get(recipientAddress, Optional.empty())
                : Optional.empty();

        if (recipientNum.isPresent()
                && traceProperties.contractFilterCheck(
                        CommonUtils.hex(toEvmAddress(((Entity) recipientNum.get()).getId())))) {
            return;
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L21-21)
```java
    private boolean enabled = false;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L33-35)
```java
    public boolean contractFilterCheck(String contract) {
        return !getContract().isEmpty() && !getContract().contains(contract);
    }
```
