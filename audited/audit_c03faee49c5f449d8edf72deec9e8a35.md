### Title
Contract Filter Bypass for System Contracts Without Entity Records in `MirrorOperationActionTracer.tracePostExecution()`

### Summary
In `MirrorOperationActionTracer.tracePostExecution()`, the `contractFilterCheck()` call is guarded by `recipientNum.isPresent()`. System contracts such as the HTS precompile at `0x0000000000000000000000000000000000000167` (entity 0.0.359) may have no row in the mirror node entity table, causing `commonEntityAccessor.get()` to return `Optional.empty()`. When that happens the filter guard short-circuits to `false` and the trace record is emitted unconditionally, bypassing any operator-configured contract allowlist. Any unprivileged user who submits a transaction that touches the HTS precompile can therefore force trace records for that system contract to be produced even when the operator explicitly excluded it.

### Finding Description
**File:** `web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/MirrorOperationActionTracer.java`, lines 59–68
**Filter definition:** `web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java`, lines 33–35

```java
// MirrorOperationActionTracer.java  lines 59-68
final var recipientAddress = frame.getRecipientAddress();
final var recipientNum = recipientAddress != null
        ? commonEntityAccessor.get(recipientAddress, Optional.empty())
        : Optional.empty();

if (recipientNum.isPresent()                          // ← guard
        && traceProperties.contractFilterCheck(
                CommonUtils.hex(toEvmAddress(((Entity) recipientNum.get()).getId())))) {
    return;   // filtered out
}

log.info("type={} ...", ...);   // ← always reached when recipientNum is empty
```

```java
// TraceProperties.java  lines 33-35
public boolean contractFilterCheck(String contract) {
    return !getContract().isEmpty() && !getContract().contains(contract);
}
```

**Root cause / failed assumption:** The code assumes that every address that appears as a recipient during EVM execution has a corresponding entity row in the database. System contracts (precompiles) are virtual; they are dispatched by the EVM framework and do not require a persisted entity record. `CommonEntityAccessor.get(Address, Optional)` delegates to `entityRepository.findByIdAndDeletedIsFalse(359)` for the long-zero address `0x167`. If no row exists, it returns `Optional.empty()`. The `recipientNum.isPresent()` guard then makes the entire filter expression evaluate to `false`, so `contractFilterCheck()` is never invoked and the `log.info` line is reached unconditionally.

**Exploit flow:**
1. Operator enables tracing (`hiero.mirror.web3.evm.trace.enabled=true`) and configures a contract allowlist that does **not** include the HTS precompile address, intending to suppress its trace records.
2. Attacker submits any `eth_call` or `eth_sendRawTransaction` that calls a user-deployed contract which internally calls the HTS precompile (e.g., `address(0x167).call(...)`).
3. During EVM execution `tracePostExecution` fires with `frame.getRecipientAddress()` = `0x0000000000000000000000000000000000000167`.
4. `commonEntityAccessor.get(0x167, Optional.empty())` queries `findByIdAndDeletedIsFalse(359)` → `Optional.empty()` (no entity row for the precompile).
5. `recipientNum.isPresent()` is `false`; the `return` is skipped; `log.info(...)` emits a full trace record for the system contract.

### Impact Explanation
The operator's contract filter is rendered ineffective for any system contract that lacks an entity record. Trace records for the HTS precompile (and potentially other system contracts such as the Exchange Rate precompile at `0x168` or PRNG at `0x169`) are emitted regardless of the configured allowlist. Consequences include: unintended information disclosure of internal precompile call details in logs, uncontrolled log volume growth when high-frequency HTS operations are traced, and violation of the operator's explicit security/audit policy for which contracts are monitored.

### Likelihood Explanation
Preconditions are: tracing must be enabled (off by default) and a non-empty contract filter must be configured. Both are operator choices, but the scenario is realistic in production monitoring setups. Once those conditions hold, any unprivileged user can trigger the bypass with a single contract call that touches HTS. No special privileges, keys, or accounts are required. The trigger is repeatable and deterministic.

### Recommendation
Remove the `recipientNum.isPresent()` guard from the filter decision. The filter should apply regardless of whether the entity is found in the database:

```java
// Option A – always evaluate the filter, use raw address hex when entity is absent
final var recipientAddress = frame.getRecipientAddress();
final var recipientEntity = recipientAddress != null
        ? commonEntityAccessor.get(recipientAddress, Optional.empty())
        : Optional.empty();

final String filterKey = recipientEntity
        .map(e -> CommonUtils.hex(toEvmAddress(((Entity) e).getId())))
        .orElseGet(() -> recipientAddress != null ? recipientAddress.toHexString() : "");

if (traceProperties.contractFilterCheck(filterKey)) {
    return;
}
```

Alternatively, explicitly detect system-contract addresses (long-zero addresses whose entity num falls in the system range) and apply a hard-coded exclusion before the entity lookup, so the filter is always enforced.

### Proof of Concept
1. Start mirror-node web3 with:
   ```yaml
   hiero.mirror.web3.evm.trace.enabled: true
   hiero.mirror.web3.evm.trace.contract:
     - "0x000000000000000000000000000000000000abcd"  # some other contract, NOT 0x167
   ```
2. Deploy a Solidity contract that calls `address(0x167).call(...)` (e.g., `callMissingPrecompile()` already present in `web3/src/test/solidity/PrecompileTestContract.sol` line 146–150).
3. Submit `eth_call` targeting that contract.
4. Observe in the mirror-node log that a `type=MESSAGE_CALL … recipient=0x167` line is emitted, even though `0x167` is not in the configured allowlist.
5. Confirm that `entityRepository.findByIdAndDeletedIsFalse(359)` returns empty (no entity row for the HTS precompile), causing the filter to be skipped. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/TraceProperties.java (L33-35)
```java
    public boolean contractFilterCheck(String contract) {
        return !getContract().isEmpty() && !getContract().contains(contract);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L29-36)
```java
    public @NonNull Optional<Entity> get(@NonNull final Address address, final Optional<Long> timestamp) {
        final var addressBytes = address.toArrayUnsafe();
        if (ConversionUtils.isLongZeroAddress(addressBytes)) {
            return getEntityByMirrorAddressAndTimestamp(address, timestamp);
        } else {
            return getEntityByEvmAddressTimestamp(address.toArrayUnsafe(), timestamp);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L73-78)
```java
    private Optional<Entity> getEntityByMirrorAddressAndTimestamp(Address address, final Optional<Long> timestamp) {
        final var entityId = entityIdNumFromEvmAddress(address);
        return timestamp
                .map(t -> entityRepository.findActiveByIdAndTimestamp(entityId, t))
                .orElseGet(() -> entityRepository.findByIdAndDeletedIsFalse(entityId));
    }
```

**File:** web3/src/test/solidity/PrecompileTestContract.sol (L146-150)
```text
    function callMissingPrecompile() public returns (bool success, bytes memory result) {
        (success, result) = address(0x167).call(
            abi.encodeWithSignature("fakeSignature()"));
        require(success);
    }
```
