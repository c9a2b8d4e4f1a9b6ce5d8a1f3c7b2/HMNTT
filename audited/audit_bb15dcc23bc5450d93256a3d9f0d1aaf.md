### Title
Unauthenticated Storage Slot Exposure via Opcode Replay Endpoint

### Summary
The `getContractOpcodes()` endpoint at `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` has no authentication or authorization controls. Any unprivileged external user can supply any public transaction ID or hash and request `storage=true`, causing the mirror node to re-execute the transaction on the EVM and return all storage slot key-value pairs accessed during execution — including sensitive data stored in contracts such as vesting schedules (cliff, duration, amount per beneficiary).

### Finding Description
**Exact code path:**

`OpcodesController.java:52-68` — `getContractOpcodes()` performs three checks before serving the response:
1. `properties.isEnabled()` — a feature flag (`hiero.mirror.web3.opcode.tracer.enabled`, default `false`); when enabled by an operator this is the only gate.
2. `validateAcceptEncodingHeader()` — requires `Accept-Encoding: gzip`; trivially satisfied.
3. `throttleManager.throttleOpcodeRequest()` — rate-limiting only, not access control.

There is no `@PreAuthorize`, `@Secured`, `SecurityFilterChain`, or any Spring Security configuration anywhere in the web3 module (confirmed by exhaustive search returning zero matches).

**Root cause:** The endpoint was designed as a debug/tracing tool but was exposed publicly without any caller identity check. The `storage` boolean flag is accepted from any caller and passed directly into `OpcodeRequest`, then into `OpcodeContext`.

**Storage capture path:**
`OpcodeServiceImpl.processOpcodeCall()` → `ContractDebugService.processOpcodeCall()` → EVM replay → `OpcodeActionTracer.tracePostExecution()` → `AbstractOpcodeTracer.captureStorage()`.

In `AbstractOpcodeTracer.captureStorage()` (lines 75–128), when `options.isStorage()` is `true`, the tracer reads **all** storage accesses from `rootProxyWorldUpdater.getEvmFrameState().getTxStorageUsage(true).accesses()` — every slot key and its read or written value — and returns them as a `Map<String, String>` in the `Opcode` response objects.

For a vesting contract, storage slots holding `cliff`, `duration`, and `amount` per beneficiary are accessed during any `vest()` or `claim()` call. These raw 32-byte hex values are returned in the `storage` field of each `Opcode` entry in the response.

**Why existing checks fail:**
- The feature flag is an operator toggle, not a per-caller access control.
- The gzip header requirement is a transport optimization, not a security gate.
- Rate limiting slows but does not prevent the attack; a single request is sufficient to extract all storage for a given transaction.

### Impact Explanation
When the opcode tracer is enabled, any anonymous HTTP client can retrieve the complete storage trace of any historical contract transaction. For a token vesting contract, this means:
- Exact vesting amounts, cliff timestamps, and durations for named beneficiaries are exposed.
- An attacker who observes a beneficiary's address interacting with the vesting contract (public on-chain) can immediately retrieve their full compensation schedule.
- The data is returned in structured, machine-readable hex format, trivially decodable with ABI knowledge.

Severity: **High** — confidential compensation data is directly leaked to unauthenticated callers.

### Likelihood Explanation
- Transaction hashes and IDs are fully public on any Hedera mirror node.
- The HTTP request requires only a `Accept-Encoding: gzip` header — no credentials, no API key, no wallet signature.
- The attack is a single GET request, repeatable indefinitely (subject only to rate limiting).
- Any operator who enables the feature for legitimate debugging purposes simultaneously exposes all historical contract storage to the public internet.

### Recommendation
1. **Add authentication/authorization** to the opcodes endpoint. At minimum, require an API key or operator-issued bearer token. Ideally, gate the endpoint behind a Spring Security `SecurityFilterChain` rule requiring an authenticated role (e.g., `ROLE_ADMIN` or `ROLE_DEBUGGER`).
2. **Restrict the `storage` parameter** to authenticated callers only, even if the base endpoint is public.
3. Consider making the endpoint **internal-only** (e.g., bound to a management port or behind a network policy) rather than exposing it on the public API path `/api/v1/`.
4. Add an explicit test asserting that unauthenticated requests to the opcodes endpoint are rejected with HTTP 401/403.

### Proof of Concept
**Preconditions:**
- Mirror node deployed with `hiero.mirror.web3.opcode.tracer.enabled=true`.
- A vesting contract has been called on-chain; the transaction hash is known (public).

**Steps:**
```
# 1. Obtain any transaction hash that called the vesting contract
TX_HASH=0xabc123...   # public, from mirror node /api/v1/contracts/results

# 2. Call the opcodes endpoint as an unauthenticated user
curl -s -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?storage=true" \
  --compressed | jq '.opcodes[].storage'
```

**Result:** Each opcode entry's `storage` field contains a map of slot keys → values. For a vesting contract, entries such as:
```json
{
  "0x<keccak(beneficiary_addr ++ slot_0)>": "0x000...cliff_timestamp",
  "0x<keccak(beneficiary_addr ++ slot_1)>": "0x000...duration",
  "0x<keccak(beneficiary_addr ++ slot_2)>": "0x000...amount"
}
```
are returned, fully exposing the beneficiary's vesting parameters to the unauthenticated caller. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-68)
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

        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L1-12)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.controller;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "hiero.mirror.web3.opcode.tracer")
@Data
public class OpcodesProperties {
    private boolean enabled = false;
}
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L75-128)
```java
    protected Map<String, String> captureStorage(
            final MessageFrame frame, final OpcodeContext options, final ContractCallContext context) {
        if (!options.isStorage()) {
            return Collections.emptyMap();
        }

        try {
            if (context.getOpcodeContext().getRootProxyWorldUpdater() == null) {

                var worldUpdater = frame.getWorldUpdater();
                var parent = worldUpdater.parentUpdater().orElse(null);
                while (parent != null) {
                    worldUpdater = parent;
                    parent = worldUpdater.parentUpdater().orElse(null);
                }

                if (!(worldUpdater instanceof RootProxyWorldUpdater rootProxyWorldUpdater)) {
                    // The storage updates are kept only in the RootProxyWorldUpdater.
                    // If we don't have one -> something unexpected happened and an attempt to
                    // get the storage changes from a ProxyWorldUpdater would result in a
                    // NullPointerException, so in this case just return an empty map.
                    return Collections.emptyMap();
                }

                context.getOpcodeContext().setRootProxyWorldUpdater(rootProxyWorldUpdater);
            }

            final var rootProxyWorldUpdater = context.getOpcodeContext().getRootProxyWorldUpdater();
            final var updates = rootProxyWorldUpdater
                    .getEvmFrameState()
                    .getTxStorageUsage(true)
                    .accesses();

            if (updates.isEmpty()) {
                return Collections.emptyMap();
            }

            final var result = new TreeMap<String, String>();
            for (final var storageAccesses : updates) {
                for (final var access : storageAccesses.accesses()) {
                    final var key = hexCache.get(access.key(), Bytes::toHexString);
                    if (!result.containsKey(key)) {
                        final var value = access.writtenValue() != null
                                ? hexCache.get(access.writtenValue(), Bytes::toHexString)
                                : hexCache.get(access.value(), Bytes::toHexString);
                        result.put(key, value);
                    }
                }
            }
            return result;

        } catch (final ModificationNotAllowedException e) {
            return Collections.emptyMap();
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeActionTracer.java (L44-62)
```java
    public void tracePostExecution(@NonNull final MessageFrame frame, @NonNull final OperationResult operationResult) {
        final var context = ContractCallContext.get();

        // Reset the balance call flag after BALANCE opcode completes
        if (frame.getCurrentOperation() != null
                && BALANCE_OPERATION_NAME.equals(frame.getCurrentOperation().getName())) {
            context.setBalanceCall(false);
        }

        final var options = context.getOpcodeContext();
        final var memory = captureMemory(frame, options);
        final var stack = captureStack(frame, options);
        final var storage = captureStorage(frame, options, context);

        final var revertReasonBytes = frame.getRevertReason().orElse(null);
        final var reason = revertReasonBytes != null ? revertReasonBytes.toHexString() : null;
        context.getOpcodeContext()
                .addOpcodes(createOpcode(frame, operationResult.getGasCost(), reason, stack, memory, storage));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L63-74)
```java
    @Override
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
