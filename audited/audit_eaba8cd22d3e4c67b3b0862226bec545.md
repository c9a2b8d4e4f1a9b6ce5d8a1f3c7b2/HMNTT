### Title
Unbounded `ContractCallRequest` Logging in `ThrottleManagerImpl.action()` Enables Log-Disk Exhaustion via Large `data` Field

### Summary
When a `RequestProperties` entry is configured with `action = LOG` (the default action type), `ThrottleManagerImpl.action()` calls `log.info("{}", request)` which serializes the full `ContractCallRequest` object including its `data` field. The `data` field accepts up to 1,048,576 characters by default (the `@Hex` annotation's `maxLength` default), and the `maxPayloadLogSize` truncation guard present in `LoggingFilter` is never applied to this code path. An unprivileged external user can craft requests that match the configured filter and carry a near-1 MB `data` payload, causing the logger to emit multi-megabyte lines at the full configured request rate.

### Finding Description

**Exact code path:**

`ThrottleManagerImpl.java`, `action()`, line 68: [1](#0-0) 

```java
private void action(RequestProperties filter, ContractCallRequest request) {
    switch (filter.getAction()) {
        case LOG -> log.info("{}", request);   // ← full toString(), no truncation
```

`log.info("{}", request)` invokes Lombok's generated `ContractCallRequest.toString()`, which includes every field verbatim — in particular `data`.

**Root cause — no size cap on `data` in this path:**

`ContractCallRequest.data` carries only `@Hex` with the default `maxLength = 1_048_576L`: [2](#0-1) [3](#0-2) 

That is 1 MB of hex characters per request, all of which end up in the log line.

**Why the existing guard does not help:**

`maxPayloadLogSize` (default 300 chars) is enforced exclusively inside `LoggingFilter.getContent()`, which truncates the raw HTTP body captured by `ContentCachingRequestWrapper`: [4](#0-3) 

`ThrottleManagerImpl.action()` is called from inside the filter chain, before `LoggingFilter` has a chance to post-process anything, and it uses its own independent `log.info` call — completely bypassing `maxPayloadLogSize`.

**Default configuration makes this easy to trigger:**

`RequestProperties.action` defaults to `LOG`: [5](#0-4) 

When `filters` is empty, every request matches: [6](#0-5) 

At `rate = 100` (default), the sampling check `randomLong(0, 100) >= 100` is never true, so 100 % of matching requests are logged: [7](#0-6) 

### Impact Explanation
Each matching request can produce a log line of up to ~1 MB. At the default global rate limit of 500 req/s (`requestsPerSecond = 500`), a sustained attack generates up to ~500 MB/s of log output. This can exhaust disk space on the node, fill log-shipping pipelines, degrade observability, and in extreme cases crash the JVM's logging subsystem — all without any economic cost to the attacker and with no impact on the Hedera network itself. Severity matches the stated scope: griefing with no on-chain economic damage.

### Likelihood Explanation
The precondition is that at least one `RequestProperties` entry with `action = LOG` exists in the operator's configuration — which is the default action type. Any anonymous HTTP client can send a POST to `/api/v1/contracts/call` with a `data` field of up to 1 MB of valid hex characters. No authentication, no special role, no prior knowledge beyond the public API is required. The attack is trivially repeatable in a loop up to the global RPS limit.

### Recommendation
Apply `maxPayloadLogSize` truncation inside `action()` before logging:

```java
case LOG -> {
    var repr = request.toString();
    if (repr.length() > throttleProperties.getMaxPayloadLogSize()) {
        repr = repr.substring(0, throttleProperties.getMaxPayloadLogSize()) + "…";
    }
    log.info("{}", repr);
}
```

Alternatively, add an explicit `@Size(max = …)` or reduce the `@Hex` default `maxLength` to a value consistent with realistic EVM calldata, and/or inject `Web3Properties` into `ThrottleManagerImpl` and reuse the existing `maxPayloadLogSize` property.

### Proof of Concept

```bash
# 1. Ensure the operator has at least one RequestProperties with action=LOG
#    (this is the default; no special config needed if a request[] entry exists)

# 2. Build a 1 MB hex payload
PAYLOAD=$(python3 -c "print('0x' + 'aa' * 524288)")

# 3. Send the request repeatedly up to the RPS limit
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"data\":\"$PAYLOAD\",\"to\":\"0x0000000000000000000000000000000000000001\",\"gas\":21000}" &
done
wait

# 4. Observe: each matched request emits a ~1 MB log.info line in the application log,
#    totalling ~500 MB of log output per second of sustained attack.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L66-68)
```java
    private void action(RequestProperties filter, ContractCallRequest request) {
        switch (filter.getAction()) {
            case LOG -> log.info("{}", request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/validation/Hex.java (L27-27)
```java
    long maxLength() default 1048576L;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L28-29)
```java
    @Hex
    private String data;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L80-108)
```java
    private String getContent(HttpServletRequest request, int status) {
        var content = StringUtils.EMPTY;
        final int maxPayloadLogSize = web3Properties.getMaxPayloadLogSize();
        final var wrapper = WebUtils.getNativeRequest(request, ContentCachingRequestWrapper.class);

        if (wrapper != null) {
            content = StringUtils.deleteWhitespace(wrapper.getContentAsString());
        }

        if (content.length() > maxPayloadLogSize) {
            final var bos = new ByteArrayOutputStream(content.length() / 4);
            try (final var out = new GZIPOutputStream(bos)) {
                out.write(content.getBytes(StandardCharsets.UTF_8));
                out.finish();
                final var compressed = Base64.getEncoder().encodeToString(bos.toByteArray());

                if (compressed.length() <= maxPayloadLogSize) {
                    content = compressed;
                }
            } catch (Exception e) {
                // Ignore
            }
        }

        // Truncate log message size unless it's a 5xx error
        if (content.length() > maxPayloadLogSize && status < HttpStatus.INTERNAL_SERVER_ERROR.value()) {
            content = reorderFields(content);
            content = StringUtils.substring(content, 0, maxPayloadLogSize);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L29-29)
```java
    private ActionType action = ActionType.LOG;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L50-51)
```java
        if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
            return false;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L54-60)
```java
        for (var filter : filters) {
            if (filter.test(contractCallRequest)) {
                return true;
            }
        }

        return filters.isEmpty();
```
