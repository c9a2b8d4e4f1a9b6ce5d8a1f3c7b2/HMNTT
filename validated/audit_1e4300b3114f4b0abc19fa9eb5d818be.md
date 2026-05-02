All code references check out. Let me verify the complete exploit path before rendering judgment.

**Verified facts:**

1. `GenericControllerAdvice.mirrorEvmTransactionError()` at line 98 explicitly sets `ERROR_EXCEPTION_ATTRIBUTE` on the request with the full `MirrorEvmTransactionException` object. [1](#0-0) 

2. `LoggingFilter.getMessage()` checks that attribute and calls `getFullMessage()` with no size guard. [2](#0-1) 

3. `getFullMessage()` concatenates `getMessage()`, `detail`, `childTransactionErrors`, and `data` with no cap. [3](#0-2) 

4. `getContent()` does apply `maxPayloadLogSize`, but only to the request body, and notably skips truncation entirely for 5xx responses. [4](#0-3) 

5. `data` is sourced directly from the raw hex revert output in `validateResult()`. [5](#0-4) 

6. `maxPayloadLogSize` defaults to 300. [6](#0-5) 

**SECURITY.md scope check:** The out-of-scope list includes *"Impacts that only require DDoS"* — meaning volumetric, distributed attacks. This vulnerability requires only a **single crafted request** to produce an oversized log entry, which is a single-request amplification, not a DDoS. It is not excluded. [7](#0-6) 

All four required checks pass. The finding is in scope and technically accurate.

---

Audit Report

## Title
Unbounded Log Entry via Unsized `getMessage()` Bypass of `maxPayloadLogSize` in `LoggingFilter`

## Summary
`LoggingFilter.getMessage()` returns the full `MirrorEvmTransactionException.getFullMessage()` string — including raw hex revert data (`data`) and decoded revert string (`detail`) — without applying any size limit. `getContent()` enforces `maxPayloadLogSize` on the request body, but `getMessage()` has no equivalent guard, allowing an unprivileged caller to force arbitrarily large log entries by submitting a transaction that reverts with a large EVM payload.

## Finding Description

**Exploit path:**

`GenericControllerAdvice.mirrorEvmTransactionError()` handles every `MirrorEvmTransactionException` and explicitly stores it as `ERROR_EXCEPTION_ATTRIBUTE` on the request: [1](#0-0) 

`LoggingFilter.getMessage()` then retrieves that attribute and calls `getFullMessage()` with no size limit: [8](#0-7) 

`getFullMessage()` concatenates all fields — `getMessage()`, `detail`, `childTransactionErrors`, and `data` — without any cap: [3](#0-2) 

The `data` field is populated from the raw hex of the EVM revert output, and `detail` from the decoded Solidity error string, both sourced in `ContractCallService.validateResult()`: [9](#0-8) 

By contrast, `getContent()` does apply `maxPayloadLogSize` — but only to the request body, and it skips truncation entirely for 5xx responses: [4](#0-3) 

Both `content` and `message` are assembled into `LOG_FORMAT` and emitted in the same log call: [10](#0-9) [11](#0-10) 

**Root cause:** The assumption that `maxPayloadLogSize` bounds all logged content is broken. The property controls only `getContent()` (request body), not `getMessage()` (exception message). The default value is 300 characters: [6](#0-5) 

## Impact Explanation
An attacker can force log entries of arbitrary size (bounded only by EVM gas limits, not by `maxPayloadLogSize`). Repeated requests can flood log storage, exhaust disk space on the mirror node host, degrade or crash the logging subsystem, and obscure legitimate log entries. The default `maxPayloadLogSize` of 300 characters is rendered meaningless for the exception-message portion of every log line.

## Likelihood Explanation
No authentication or special privilege is required. Any caller of the public `eth_call` or contract-creation simulation endpoint can trigger this. The attack is trivially repeatable: submit one request per desired log line. Gas throttling limits throughput but does not prevent the attack, since even a single reverted call with a few KB of revert data already produces a log entry orders of magnitude larger than the intended 300-character limit.

## Recommendation
Apply the same `maxPayloadLogSize` truncation in `getMessage()` that `getContent()` applies to the request body. Specifically, after building the string from `getFullMessage()`, truncate it to `web3Properties.getMaxPayloadLogSize()` before returning. A secondary hardening step is to also apply truncation to `getContent()` for 5xx responses (currently skipped at line 105), since the current exemption for server errors also allows unbounded content logging.

## Proof of Concept
1. Deploy or target any contract that reverts with a large custom error payload (e.g., a `revert` with a `bytes` argument filled with several KB of data).
2. Submit an `eth_call` request to `/api/v1/contracts/call` targeting that contract.
3. The EVM executes, reverts, and `ContractCallService.validateResult()` throws a `MirrorEvmTransactionException` with `data` = the full hex revert payload.
4. `GenericControllerAdvice.mirrorEvmTransactionError()` catches it, sets it as `ERROR_EXCEPTION_ATTRIBUTE`, and returns a 400 response.
5. `LoggingFilter.logRequest()` calls `getMessage()`, which calls `getFullMessage()`, producing a log line whose `message` segment contains the full hex payload — far exceeding the 300-character `maxPayloadLogSize`.
6. Repeat to fill disk or overwhelm the logging subsystem.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L96-98)
```java
    private ResponseEntity<?> mirrorEvmTransactionError(
            final MirrorEvmTransactionException e, final WebRequest request) {
        request.setAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, e, SCOPE_REQUEST);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L34-34)
```java
    private static final String LOG_FORMAT = "{} {} {} in {} ms : {} {} - {}";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L71-77)
```java
        if (actuator) {
            log.debug(LOG_FORMAT, params);
        } else if (status >= HttpStatus.INTERNAL_SERVER_ERROR.value()) {
            log.warn(LOG_FORMAT, params);
        } else {
            log.info(LOG_FORMAT, params);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L104-108)
```java
        // Truncate log message size unless it's a 5xx error
        if (content.length() > maxPayloadLogSize && status < HttpStatus.INTERNAL_SERVER_ERROR.value()) {
            content = reorderFields(content);
            content = StringUtils.substring(content, 0, maxPayloadLogSize);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L113-126)
```java
    private String getMessage(HttpServletRequest request, Exception e) {
        if (e != null) {
            return e.getMessage();
        }

        if (request.getAttribute(ERROR_EXCEPTION_ATTRIBUTE) instanceof Exception ex) {
            if (ex instanceof MirrorEvmTransactionException mirrorEvmTransactionException) {
                return mirrorEvmTransactionException.getFullMessage();
            }
            return ex.getMessage();
        }

        return SUCCESS;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/exception/MirrorEvmTransactionException.java (L67-78)
```java
    public String getFullMessage() {
        final var exceptionMessageBuilder =
                new StringBuilder().append("Mirror EVM transaction error: ").append(getMessage());
        if (!StringUtils.isBlank(getDetail())) {
            exceptionMessageBuilder.append(", detail: ").append(getDetail());
        }
        if (getChildTransactionErrors() != null && !getChildTransactionErrors().isEmpty()) {
            exceptionMessageBuilder.append(", childTransactionErrors: ").append(getChildTransactionErrors());
        }
        exceptionMessageBuilder.append(", data: ").append(getData());
        return exceptionMessageBuilder.toString();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L154-161)
```java
    protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
        if (!txnResult.isSuccessful()) {
            var revertReasonHex = txnResult.getErrorMessage().orElse(HEX_PREFIX);
            var detail = maybeDecodeSolidityErrorStringToReadableMessage(revertReasonHex);
            throw new MirrorEvmTransactionException(
                    txnResult.responseCodeEnum().protoName(), detail, revertReasonHex, txnResult);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L17-17)
```java
    private int maxPayloadLogSize = 300;
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
