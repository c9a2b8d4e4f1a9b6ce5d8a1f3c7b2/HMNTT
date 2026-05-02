Looking at the code carefully to trace the full path from transaction submission to logging.

### Title
Unbounded Log Entry via Unsized `MirrorEvmTransactionException.getFullMessage()` in `LoggingFilter.getMessage()`

### Summary
`LoggingFilter.getMessage()` returns `MirrorEvmTransactionException.getFullMessage()` verbatim, with no size cap. `getFullMessage()` concatenates the EVM response code, the decoded revert detail string, child transaction errors, and the raw hex-encoded revert data — all of which are attacker-influenced. Because `maxPayloadLogSize` is only enforced on the request-body path (`getContent()`), an unprivileged caller can force arbitrarily large log lines by triggering a contract revert that returns a large payload.

### Finding Description

**Code path:**

`ContractCallService.validateResult()` ( [1](#0-0) ) builds the exception:

```java
var revertReasonHex = txnResult.getErrorMessage().orElse(HEX_PREFIX);   // raw EVM revert bytes as hex
var detail = maybeDecodeSolidityErrorStringToReadableMessage(revertReasonHex); // decoded string
throw new MirrorEvmTransactionException(
        txnResult.responseCodeEnum().protoName(), detail, revertReasonHex, txnResult);
```

`revertReasonHex` is the full hex-encoded revert payload returned by the EVM — its size is bounded only by EVM memory, not by any application-level limit.

`MirrorEvmTransactionException.getFullMessage()` ( [2](#0-1) ) concatenates all fields without truncation:

```java
exceptionMessageBuilder.append("Mirror EVM transaction error: ").append(getMessage());
// ...detail...
// ...childTransactionErrors...
exceptionMessageBuilder.append(", data: ").append(getData());   // full hex revert payload
```

`LoggingFilter.getMessage()` ( [3](#0-2) ) returns this string directly:

```java
if (ex instanceof MirrorEvmTransactionException mirrorEvmTransactionException) {
    return mirrorEvmTransactionException.getFullMessage();   // no size limit applied
}
```

`logRequest()` then logs both `content` and `message` ( [4](#0-3) ). `content` is capped by `maxPayloadLogSize` (default 300) inside `getContent()` ( [5](#0-4) ), but `message` is never capped.

**Failed assumption:** The developer applied `maxPayloadLogSize` only to the request body (`getContent()`), assuming the exception message would be short. The `data` field of `MirrorEvmTransactionException` is the raw EVM revert payload, which is fully attacker-controlled in size.

### Impact Explanation
Every `eth_call` or `eth_estimateGas` request that triggers a contract revert produces a log line whose `message` segment is proportional to the revert payload size. An attacker can repeatedly submit calls that revert with a large payload (e.g., a contract that returns a 64 KB revert string), generating log lines of 128 KB+ each (hex encoding doubles size). At scale this causes: disk exhaustion on the mirror node host, log-pipeline saturation (e.g., Elasticsearch, Splunk), and degraded observability for operators. The `maxPayloadLogSize` setting provides a false sense of protection — it is completely bypassed for the `message` field.

### Likelihood Explanation
The web3 JSON-RPC endpoint (`eth_call`, `eth_estimateGas`) requires no authentication. Any internet-accessible mirror node is reachable. The attacker only needs to call any deployed contract that reverts with a large payload — or, if contract deployment is available via the mirror node's simulation, deploy one themselves. The attack is trivially repeatable in a tight loop. Existing contracts on Hedera mainnet that revert with large custom errors already satisfy the precondition.

### Recommendation
Apply `maxPayloadLogSize` to the `message` string inside `getMessage()` before returning it, mirroring the truncation already applied to `content`:

```java
private String getMessage(HttpServletRequest request, Exception e) {
    String raw;
    if (e != null) {
        raw = e.getMessage();
    } else if (request.getAttribute(ERROR_EXCEPTION_ATTRIBUTE) instanceof Exception ex) {
        raw = (ex instanceof MirrorEvmTransactionException mete)
                ? mete.getFullMessage() : ex.getMessage();
    } else {
        return SUCCESS;
    }
    int max = web3Properties.getMaxPayloadLogSize();
    return (raw != null && raw.length() > max)
            ? StringUtils.substring(raw, 0, max) + "…"
            : raw;
}
```

Alternatively, add a dedicated `maxMessageLogSize` property so operators can tune the two limits independently.

### Proof of Concept

1. Identify or deploy a Solidity contract on the target mirror node that executes `revert(string(new bytes(65536)))` — a 64 KB revert payload.
2. Send a POST to the mirror node's `eth_call` endpoint:
   ```json
   {"jsonrpc":"2.0","method":"eth_call",
    "params":[{"to":"<contract_address>","data":"<revert_fn_selector>"},"latest"],
    "id":1}
   ```
3. Observe the application log. The logged line contains a `data:` segment of ~131 072 hex characters (2× the 64 KB payload), far exceeding `maxPayloadLogSize = 300`.
4. Repeat in a loop (e.g., 1 000 req/s). Each request writes ~128 KB to the log, producing ~128 MB/s of log output, exhausting disk or log-shipping capacity regardless of the configured `maxPayloadLogSize`.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L154-160)
```java
    protected void validateResult(final EvmTransactionResult txnResult, final CallServiceParameters params) {
        if (!txnResult.isSuccessful()) {
            var revertReasonHex = txnResult.getErrorMessage().orElse(HEX_PREFIX);
            var detail = maybeDecodeSolidityErrorStringToReadableMessage(revertReasonHex);
            throw new MirrorEvmTransactionException(
                    txnResult.responseCodeEnum().protoName(), detail, revertReasonHex, txnResult);
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
