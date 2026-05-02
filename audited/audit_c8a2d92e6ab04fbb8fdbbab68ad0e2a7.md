### Title
Unauthenticated Access to Opcode Debug Endpoint Exposes Full EVM Execution State Including System Contract Storage Accesses

### Summary
The `getContractOpcodes()` endpoint in `OpcodesController` performs no authentication or authorization check. Any unprivileged external user can query any historical transaction's full EVM re-execution trace — including raw stack, memory, and all storage accesses — when the feature flag is enabled. For transactions involving Hedera system/precompile contracts, the storage capture reads all storage accesses across the entire transaction (including internal system contract state), and `tracePrecompileResult` records gas costs and ABI-encoded internal revert reasons from system contract actions.

### Finding Description
**Code path:**

`OpcodesController.java:52-68` — `getContractOpcodes()` has three gates: `properties.isEnabled()` (a config flag, default `false`), a gzip header check, and a rate limiter. There is no `@PreAuthorize`, `@Secured`, Spring Security filter, or any identity check. A grep across all of `web3/src/main/java/**/*.java` confirms zero Spring Security annotations exist in the module. [1](#0-0) 

`OpcodesProperties.java:11` — `enabled` defaults to `false`, but this is a deployment configuration toggle, not an access-control mechanism. When an operator enables the feature, the endpoint becomes fully public. [2](#0-1) 

**Precompile execution details exposed:**

`OpcodeActionTracer.java:96-115` — `tracePrecompileResult()` is called for every precompile/system contract invocation. It records an `Opcode` entry containing: program counter, operation name, remaining gas, computed gas cost, call depth, and — critically — the revert reason. For calls to Hedera system contracts (HTS, exchange rate, etc.), the revert reason is sourced from `getRevertReasonFromContractActions()`, which ABI-encodes internal Hedera `ResponseCodeEnum` values (e.g., `INVALID_ACCOUNT_ID`, `TOKEN_NOT_ASSOCIATED_TO_ACCOUNT`) from the stored `ContractAction` records. [3](#0-2) 

`AbstractOpcodeTracer.java:75-129` — `captureStorage()` (called on every `tracePostExecution`) traverses the `RootProxyWorldUpdater` and calls `getTxStorageUsage(true).accesses()`, which returns **all** storage slot reads and writes for the entire transaction — including those performed by system contracts during precompile execution. This raw slot-level data is included in every `Opcode` entry when `storage=true`. [4](#0-3) 

`AbstractOpcodeTracer.java:40-58` — `captureMemory()` dumps the entire EVM memory word-by-word when `memory=true`. At the opcode step immediately before a precompile CALL, the memory contains the ABI-encoded calldata being passed to the precompile (token addresses, amounts, account IDs, etc.). [5](#0-4) 

**Failed assumption:** The design assumes that `enabled=false` as a default is sufficient protection. It is not — it is a feature toggle, not an authorization boundary. Once enabled (e.g., for debugging or by operator misconfiguration), the endpoint is fully open to the internet.

### Impact Explanation
Any unauthenticated caller who knows (or can enumerate) a valid `transactionIdOrHash` can:
1. Obtain the full opcode-by-opcode execution trace of any historical transaction, including raw EVM stack, memory, and storage state at every step.
2. Observe all storage slot accesses made by Hedera system contracts (HTS, exchange rate precompile) during transaction replay — raw internal state not normally surfaced through public APIs.
3. Obtain ABI-encoded internal Hedera response codes from failed system contract calls, revealing internal system behavior.
4. Trigger expensive transaction re-executions (the endpoint re-runs the EVM) — the rate limiter is the only mitigation, and it is bypassable from multiple IPs.

Transaction IDs and hashes are publicly visible on the Hedera mirror node REST API, so enumeration requires no privilege.

### Likelihood Explanation
- The feature is disabled by default, but operators enabling it for debugging or monitoring expose the endpoint to all users simultaneously.
- No credential, API key, IP allowlist, or role check exists anywhere in the code path.
- Transaction IDs are publicly enumerable from `/api/v1/contracts/results`.
- The exploit requires only an HTTP GET with an `Accept-Encoding: gzip` header — trivially reproducible with `curl`.
- Rate limiting (`throttleOpcodeRequest`) provides partial DoS mitigation but does not prevent information disclosure.

### Recommendation
1. Add authentication/authorization to `getContractOpcodes()`. At minimum, require an API key or restrict to a configured IP allowlist via a Spring Security `SecurityFilterChain` or `@PreAuthorize` annotation.
2. Treat `enabled=true` as a privileged mode: gate it behind both the config flag and an identity check, so enabling the feature does not automatically expose it publicly.
3. Consider whether `storage=true` should be restricted further, as it exposes raw system contract storage slot accesses that are not available through any other public API.

### Proof of Concept
```bash
# 1. Enumerate a valid transaction hash from the public mirror node REST API
TX_HASH=$(curl -s "https://<mirror-node>/api/v1/contracts/results?limit=1" \
  | jq -r '.results[0].hash')

# 2. Call the opcode endpoint as an unauthenticated user
#    with stack, memory, and storage all enabled
curl -s \
  -H "Accept-Encoding: gzip" \
  "https://<web3-mirror-node>/api/v1/contracts/results/${TX_HASH}/opcodes?stack=true&memory=true&storage=true" \
  | gunzip \
  | jq '.opcodes[] | {op, gas, gasCost, stack, memory, storage, reason}'
```

The response will contain the full opcode trace including raw EVM memory contents at each step (revealing calldata passed to precompiles), all storage slot accesses (including system contract internal state), and ABI-encoded revert reasons from system contract actions — all without any credential.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L11-11)
```java
    private boolean enabled = false;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeActionTracer.java (L96-115)
```java
    public void tracePrecompileResult(@NonNull MessageFrame frame, @NonNull ContractActionType type) {
        final var context = ContractCallContext.get();
        final var gasCost = context.getOpcodeContext().getGasRemaining() - frame.getRemainingGas();

        final var frameRevertReason = frame.getRevertReason().orElse(null);
        final var revertReason = isCallToSystemContracts(frame, systemContracts)
                ? getRevertReasonFromContractActions(context)
                : (frameRevertReason != null ? frameRevertReason.toHexString() : null);

        context.getOpcodeContext()
                .addOpcodes(createOpcode(
                        frame,
                        gasCost,
                        revertReason,
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyMap()));

        context.getOpcodeContext().setGasRemaining(frame.getRemainingGas());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L40-58)
```java
    protected final List<String> captureMemory(final MessageFrame frame, final OpcodeContext options) {
        if (!options.isMemory()) {
            return Collections.emptyList();
        }
        var size = frame.memoryWordSize();
        var hexMemoryEntries = new ArrayList<String>(size);

        final var wordSize = 32;
        final var memory = frame.readMutableMemory(0L, (long) wordSize * size).toArrayUnsafe();
        final var hex = HexFormat.of();

        for (var i = 0; i < size; i++) {
            var startIndex = i * wordSize;
            final var result = HEX_PREFIX + hex.formatHex(memory, startIndex, startIndex + wordSize);
            hexMemoryEntries.add(result);
        }

        return hexMemoryEntries;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L75-129)
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
    }
```
