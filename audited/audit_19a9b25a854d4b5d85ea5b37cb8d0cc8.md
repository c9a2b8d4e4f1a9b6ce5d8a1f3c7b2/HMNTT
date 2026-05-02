### Title
Unauthenticated Access to Full EVM Execution Traces for Failed Transactions via Opcodes Endpoint

### Summary
The `GET /api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint in `OpcodesController` has no authentication or authorization controls. When the feature flag is enabled, any unauthenticated external user can supply the hash of a failed transaction and receive a full EVM re-execution trace — including decoded revert reasons, per-opcode stack contents, memory words, and storage slot accesses — none of which are present in the original transaction receipt.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` performs only three checks before delegating to `OpcodeService`: [1](#0-0) 

1. `properties.isEnabled()` — a feature flag (defaults to `false`, but when `true` the endpoint is fully open).
2. `validateAcceptEncodingHeader()` — requires `Accept-Encoding: gzip`, a trivial header to supply.
3. `throttleManager.throttleOpcodeRequest()` — rate-limiting only, no identity check.

There is no Spring Security configuration, no `@PreAuthorize`/`@Secured` annotation, and no API-key or session check anywhere in the web3 module. [2](#0-1) 

**Root cause — failed transactions are silently re-executed and their full trace is returned:**

`ContractDebugService.validateResult()` overrides the parent's validation and **catches** `MirrorEvmTransactionException` instead of propagating it: [3](#0-2) 

This means a failed (reverted) transaction is re-executed on the EVM and its complete `OpcodesProcessingResult` — including all captured opcodes — is returned to the caller with HTTP 200. The `failed` flag in the response is set to `true`, but the full trace is still included: [4](#0-3) 

**Revert reason decoding:**

`AbstractOpcodeTracer.formatRevertReason()` decodes the raw revert bytes into a human-readable ABI-encoded string (or Hedera response-code name), and `getRevertReasonFromContractActions()` pulls the revert reason from stored contract actions for system-contract calls: [5](#0-4) [6](#0-5) 

Each `Opcode` object in the response carries a `reason` field populated with this decoded revert string: [7](#0-6) 

**What is exposed beyond the original receipt:**

The original Hedera transaction receipt for a failed contract call exposes only the top-level result code (e.g., `CONTRACT_REVERT_EXECUTED`) and, at most, the raw `call_result` bytes. The opcode trace additionally exposes:
- The decoded revert reason string at the exact opcode where the revert occurred.
- Full EVM stack contents at every executed opcode (when `stack=true`, the default).
- Memory word-by-word at every step (when `memory=true`).
- All storage slot reads/writes during execution (when `storage=true`).

### Impact Explanation
An attacker can reconstruct the internal execution path of any failed contract call, including sensitive data that was in EVM memory or on the stack at the time of failure (e.g., token amounts, addresses, encoded function arguments). For contracts that embed sensitive business logic or private parameters in their revert paths, this constitutes a meaningful information-disclosure beyond what the protocol intends to make public. The decoded revert reason also reveals internal error strings that contract authors may have intended to be opaque.

### Likelihood Explanation
The precondition is that the operator has set `hiero.mirror.web3.opcode.tracer.enabled=true`. This is an opt-in feature, but it is documented and intended for production debugging use. Once enabled, exploitation requires only: (a) knowledge of a failed transaction hash (publicly observable on-chain), (b) an HTTP client that sets `Accept-Encoding: gzip`. No credentials, keys, or privileged access are needed. The attack is fully repeatable and scriptable.

### Recommendation
Add an authentication/authorization gate to the endpoint before the feature-flag check. Options include:
1. Require a configurable API key or bearer token checked in `getContractOpcodes()` before any processing.
2. Integrate Spring Security and restrict the `/api/v1/contracts/results/*/opcodes` path to authenticated roles.
3. At minimum, document that enabling the feature flag exposes full execution traces to the public internet and recommend placing the endpoint behind a network-level access control (e.g., reverse-proxy IP allowlist).

### Proof of Concept
```
# Precondition: hiero.mirror.web3.opcode.tracer.enabled=true

# 1. Obtain the hash of any failed contract transaction (publicly visible on Hedera explorer)
FAILED_TX_HASH=0xabc123...   # hash of a CONTRACT_REVERT_EXECUTED transaction

# 2. Call the opcodes endpoint with no credentials
curl -s -H "Accept-Encoding: gzip" --compressed \
  "https://<mirror-node-host>/api/v1/contracts/results/${FAILED_TX_HASH}/opcodes?stack=true&memory=true&storage=true"

# Result: HTTP 200 with full opcode trace including:
# - "failed": true
# - "opcodes": [..., {"op":"REVERT","reason":"0x08c379a0....<decoded revert string>", "stack":[...], "memory":[...]}]
# The "reason" field contains the decoded revert message not present in the original receipt.
# The "stack" and "memory" fields expose EVM internals at every step of the failed execution.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L59-65)
```java
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesProperties.java (L11-11)
```java
    private boolean enabled = false;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L62-72)
```java
    protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
        try {
            super.validateResult(txnResult, params);
        } catch (MirrorEvmTransactionException e) {
            log.warn(
                    "Transaction failed with status: {}, detail: {}, revertReason: {}",
                    txnResult.responseCodeEnum(),
                    e.getDetail(),
                    e.getData());
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L143-149)
```java
        return new OpcodesResponse()
                .address(address)
                .contractId(contractId)
                .failed(txnResult == null || !txnResult.isSuccessful())
                .gas(txnResult != null ? txnResult.gasUsed() : 0L)
                .opcodes(opcodes)
                .returnValue(returnValue);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L131-144)
```java
    protected final String getRevertReasonFromContractActions(final ContractCallContext context) {
        final var contractActions = context.getOpcodeContext().getActions();

        if (CollectionUtils.isEmpty(contractActions)) {
            return null;
        }

        for (var action : contractActions) {
            if (action.hasRevertReason()) {
                return formatRevertReason(action.getResultData());
            }
        }
        return null;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/AbstractOpcodeTracer.java (L153-171)
```java
    protected final String formatRevertReason(final byte[] revertReason) {
        if (revertReason == null || revertReason.length == 0 || isZero(revertReason)) {
            return HEX_PREFIX;
        }

        if (startsWithErrorSelector(revertReason)) {
            return HEX_PREFIX + Hex.toHexString(revertReason);
        }

        final var firstNonZero = findFirstNonZero(revertReason);
        final var trimmedLength = revertReason.length - firstNonZero;
        if (trimmedLength <= Integer.BYTES) {
            final var responseCode = ResponseCodeEnum.forNumber(toInt(revertReason, firstNonZero));
            if (responseCode != null) {
                return BytesDecoder.getAbiEncodedRevertReason(responseCode.name());
            }
        }

        return BytesDecoder.getAbiEncodedRevertReason(new String(revertReason, StandardCharsets.UTF_8));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/execution/traceability/OpcodeActionTracer.java (L100-112)
```java
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
```
