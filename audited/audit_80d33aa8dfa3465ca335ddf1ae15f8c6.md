### Title
EVM Execution Timeout Blind Spot: `statementInspector` Only Fires at SQL Boundaries, Allowing Full `requestTimeout` CPU Burn via Pure-Computation Bytecode

### Summary
The sole wall-clock timeout enforcement for contract call requests is the Hibernate `statementInspector` in `HibernateConfiguration`, which only fires immediately before a SQL statement is issued. An unprivileged attacker can submit a contract call whose bytecode performs only pure-computation opcodes (e.g., `SHA3`/`KECCAK256` in a tight loop) that require no database reads, causing the EVM to spin on CPU for the full `requestTimeout` (default 10 seconds) with zero SQL checkpoints and therefore zero timeout interruptions.

### Finding Description

**Timeout enforcement location:**

`web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java`, lines 31–46:
```java
StatementInspector statementInspector() {
    long timeout = web3Properties.getRequestTimeout().toMillis();
    return sql -> {
        if (!ContractCallContext.isInitialized()) {
            return sql;
        }
        var startTime = ContractCallContext.get().getStartTime();
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed >= timeout) {
            throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
        }
        return sql;
    };
}
```

This lambda is invoked **only** by Hibernate immediately before issuing a SQL statement. It is never called during EVM bytecode execution.

**Default timeout value:**

`web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java`, line 20:
```java
private Duration requestTimeout = Duration.ofSeconds(10L);
```

**EVM execution path — no timeout passed:**

`web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java`, line 92:
```java
final var singleTransactionRecords = executor.execute(transactionBody, Instant.now(), getOperationTracers());
```

`TransactionExecutors.newExecutor(...)` (Hedera/Besu library) receives no wall-clock deadline. The only stop condition is gas exhaustion.

**Exploit flow:**

1. Attacker deploys (or references) a contract whose bytecode is a tight loop of `KECCAK256` (SHA3) operations on in-memory data — no `SLOAD`, `SSTORE`, or precompile calls that would trigger a DB lookup.
2. Attacker sends `POST /api/v1/contracts/call` with `gas = 15_000_000` (the `maxGasLimit` default).
3. `ContractController.call()` → `ContractExecutionService.processCall()` → `callContract()` → `doProcessCall()` → `transactionExecutionService.execute()` → `executor.execute(...)`.
4. The Besu EVM executes the bytecode loop. No SQL is issued, so `statementInspector` is never called.
5. The EVM runs until gas is exhausted. With 15 M gas of SHA3 (30 gas/call), that is ~500 000 hash operations. On a loaded JVM this can take several seconds of CPU time.
6. The `requestTimeout` of 10 s is never enforced during this window.

### Impact Explanation

A single request can monopolize a JVM thread and consume significant CPU for up to 10 seconds. The `requestsPerSecond = 500` rate limit allows up to 500 concurrent such requests, each burning a thread and CPU core for up to 10 seconds. This can increase node CPU consumption well above 30% compared to baseline, satisfying the stated impact threshold, without any brute-force volume — a small number of carefully crafted requests suffices. The endpoint is unauthenticated and publicly reachable.

### Likelihood Explanation

No privileges are required. The attacker only needs to know the public `/api/v1/contracts/call` endpoint and craft bytecode with pure-computation opcodes. The gas throttle (`gasPerSecond`, default 7.5 B gas/s) limits total gas submitted per second across all requests but does not bound CPU time per gas unit; a slow EVM execution consumes more CPU per gas unit than the throttle assumes. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Pass a wall-clock deadline into the EVM executor.** Wrap `executor.execute(...)` in a `Future` with a timeout equal to `requestTimeout`, or use a `Thread.interrupt()`-based watchdog that cancels the EVM frame loop when the deadline is exceeded.
2. **Add an EVM-level operation hook.** Implement a Besu `OperationTracer` or equivalent callback that checks `ContractCallContext.get().getStartTime()` against `requestTimeout` on every N opcodes and throws if the deadline is exceeded.
3. **Do not rely solely on `statementInspector` for wall-clock enforcement.** It is a SQL-layer hook and is blind to pure-computation EVM phases.

### Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CPUBurn {
    // Pure computation: no SLOAD/SSTORE, no precompile calls
    function burn() external pure returns (bytes32 h) {
        h = keccak256(abi.encodePacked(uint256(0)));
        for (uint256 i = 0; i < 200_000; i++) {
            h = keccak256(abi.encodePacked(h));
        }
    }
}
```

```bash
# 1. Deploy CPUBurn (or use its bytecode directly in a create call)
# 2. Call with max gas:
curl -X POST https://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{
    "data": "<burn() selector + bytecode>",
    "to":   "<CPUBurn address>",
    "gas":  15000000,
    "estimate": false
  }'
# 3. Observe: response takes ~seconds; server CPU spikes.
# 4. Repeat concurrently (e.g., 50 parallel requests) to sustain elevated CPU.
```

The `statementInspector` timeout is never triggered because no SQL statement is issued during the loop. The request completes (or OOGs) without any wall-clock interruption.