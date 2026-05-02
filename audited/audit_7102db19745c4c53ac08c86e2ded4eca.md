### Title
Unbounded Log Entry via Unsized `getMessage()` Bypass of `maxPayloadLogSize` in `LoggingFilter`

### Summary
`LoggingFilter.getMessage()` returns the full `MirrorEvmTransactionException.getFullMessage()` string — which includes the raw hex revert data (`data`) and decoded revert string (`detail`) — without applying any size limit. While `getContent()` correctly enforces `maxPayloadLogSize` on the request body, `getMessage()` has no equivalent guard, allowing an unprivileged caller to force arbitrarily large log entries by submitting a transaction that reverts with a large EVM payload.

### Finding Description

**Code path:**

`LoggingFilter.getContent()` (lines 80–111) applies `maxPayloadLogSize` to the cached request body: [1](#0-0) 

`LoggingFilter.getMessage()` (lines 113–126) has **no equivalent truncation**: [2](#0-1) 

When the request attribute `ERROR_EXCEPTION_ATTRIBUTE` holds a `MirrorEvmTransactionException`, `getMessage()` calls `getFullMessage()`, which concatenates all fields without any size cap: [3](#0-2) 

The `data` field is populated from the raw hex of the EVM revert output, and `detail` from the decoded Solidity error string, both sourced directly from EVM execution in `ContractCallService.validateResult()`: [4](#0-3) 

**Root cause:** The assumption that `maxPayloadLogSize` bounds all logged content is broken. The property controls only `getContent()` (request body), not `getMessage()` (exception message). The two log fields are assembled together in `LOG_FORMAT` at line 34 and logged at lines 71–77, but only one of them is bounded. [5](#0-4) [6](#0-5) 

### Impact Explanation
An attacker can force log entries of arbitrary size (bounded only by EVM gas limits, not by `maxPayloadLogSize`). Repeated requests can flood log storage, exhaust disk space on the mirror node host, degrade or crash the logging subsystem, and obscure legitimate log entries. The default `maxPayloadLogSize` of 300 characters is rendered meaningless for the exception-message portion of every log line. [7](#0-6) 

### Likelihood Explanation
No authentication or special privilege is required. Any caller of the public `eth_call` or contract-creation simulation endpoint can trigger this. The attack is trivially repeatable: submit one request per desired log line. Gas throttling limits throughput but does not prevent the attack, since even a single reverted call with a few KB of revert data already produces a log entry orders of magnitude larger than the intended 300-character limit.

### Recommendation
Apply the same truncation logic used in `getContent()` to the return value of `getMessage()`. Specifically, after building the full message string in `getMessage()`, truncate it to `web3Properties.getMaxPayloadLogSize()` before returning. Alternatively, apply the truncation at the call site in `logRequest()` before passing `message` into the log parameters array. The fix should mirror the existing pattern:

```java
private String getMessage(HttpServletRequest request, Exception e) {
    String msg = computeMessage(request, e);
    int max = web3Properties.getMaxPayloadLogSize();
    return msg != null && msg.length() > max ? msg.substring(0, max) : msg;
}
```

### Proof of Concept

1. Send an `eth_call` (POST to `/api/v1/contracts/call`) with `to: null` and `data` set to EVM bytecode that writes a large ABI-encoded `Error(string)` payload to memory and then executes `REVERT`:
   ```json
   {
     "data": "0x<bytecode that stores N KB of 'A' chars as Error(string) and REVERTs>",
     "gas": 15000000
   }
   ```
2. The EVM executes the bytecode, reverts with the large payload.
3. `ContractCallService.validateResult()` captures the full hex revert data as `revertReasonHex` and the decoded string as `detail`.
4. `MirrorEvmTransactionException` is thrown with both fields set to large values.
5. `LoggingFilter.getMessage()` calls `getFullMessage()`, returning a string of size proportional to the revert payload — far exceeding `maxPayloadLogSize` (300).
6. The log line written by `log.info(LOG_FORMAT, params)` contains the unbounded message, confirming the bypass. [2](#0-1) [3](#0-2)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L34-34)
```java
    private static final String LOG_FORMAT = "{} {} {} in {} ms : {} {} - {}";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L66-77)
```java
        var content = getContent(request, status);
        var message = getMessage(request, e);
        var params =
                new Object[] {request.getRemoteAddr(), request.getMethod(), uri, elapsed, status, message, content};

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

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L16-17)
```java
    @Positive
    private int maxPayloadLogSize = 300;
```
