### Title
Log Flooding via Unbounded `data` Field in LOG-Action Filter Path

### Summary
When a `RequestProperties` entry with `ActionType.LOG` is configured (the default action type), `ThrottleManagerImpl.action()` calls `log.info("{}", request)`, which serializes the full `ContractCallRequest` object including its `data` field. The `data` field is bounded only by `@Hex(maxLength = 1048576L)` — up to 1,048,576 hex characters (~1 MB per request). An unprivileged attacker can repeatedly send requests with maximum-length `data` payloads that match the LOG filter, causing ~1 MB log entries per allowed request and rapidly exhausting disk space.

### Finding Description
**Code path:**

- `ContractController.call()` ( [1](#0-0) ) calls `throttleManager.throttle(request)` after Spring's `@Valid` binding.
- `ThrottleManagerImpl.throttle()` iterates `throttleProperties.getRequest()` and calls `action(requestFilter, request)` for each matching filter. [2](#0-1) 
- `action()` on a `LOG`-typed filter executes `log.info("{}", request)`, serializing the entire `ContractCallRequest` via Lombok `@Data`-generated `toString()`. [3](#0-2) 
- `ContractCallRequest.data` carries `@Hex` with default `maxLength = 1048576L`, permitting up to 1,048,576 hex characters (~1 MB string). [4](#0-3) 
- The default `ActionType` in `RequestProperties` is `LOG`, and an empty `filters` list causes every request to match (`filters.isEmpty()` → `true`). [5](#0-4) 

**Root cause:** `log.info("{}", request)` materializes the full request object — including the up-to-1 MB `data` field — into a log record without any truncation or size guard. The rate-limit bucket controls *request count* per second, not *bytes written to the log per second*.

**Why existing checks fail:**
- `@Hex(maxLength = 1048576L)` is a correctness constraint, not a security bound; 1 MB per log line is the attack payload.
- `rateLimitBucket.tryConsume(1)` caps the number of requests per second but does nothing to limit the size of each resulting log entry. [6](#0-5) 

### Impact Explanation
Each qualifying request writes up to ~1 MB to the application log. At even a modest rate limit (e.g., 100 req/s), this yields ~100 MB/s of log I/O. Sustained over minutes, this exhausts disk space on the logging volume, potentially crashing the node process or corrupting other log-dependent subsystems. No authentication is required. Impact is griefing / availability degradation with no direct economic loss to network participants — consistent with the stated Medium scope.

### Likelihood Explanation
The endpoint `POST /api/v1/contracts/call` is publicly accessible with no authentication. Crafting a request with a 1 MB hex `data` field is trivial. The attack is repeatable at the configured rate limit indefinitely. The only prerequisite is that at least one `RequestProperties` entry with `ActionType.LOG` exists in the server configuration, which is the default action type.

### Recommendation
1. **Truncate before logging:** Replace `log.info("{}", request)` with a version that caps the `data` field in the log output, e.g.:
   ```java
   case LOG -> {
       String truncatedData = request.getData() != null
           ? StringUtils.truncate(request.getData(), 256) + "…"
           : null;
       log.info("ContractCallRequest[data={}, gas={}, ...]", truncatedData, request.getGas());
   }
   ```
2. **Reduce `@Hex` default `maxLength`:** Lower `maxLength` on the `data` field in `ContractCallRequest` to a value consistent with the actual maximum EVM calldata size the node is willing to process.
3. **Add a log-rate guard:** Independently throttle the LOG action itself (e.g., sample or debounce) so that even at the request rate limit, log volume is bounded.

### Proof of Concept
```bash
# Generate a 1 MB hex payload (1,048,576 hex chars = 524,288 bytes)
DATA="0x$(python3 -c "print('aa' * 524288)")"

# Send at the rate limit repeatedly
while true; do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"data\":\"$DATA\",\"gas\":15000000,\"to\":\"0x0000000000000000000000000000000000000001\"}" &
  sleep 0.01  # adjust to stay within rateLimitBucket
done
```
Each request that passes rate-limiting and matches the LOG filter writes a ~1 MB log record. Monitor disk usage on the logging volume — it will grow at approximately `(requests_per_second) × 1 MB/s` until disk exhaustion.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-41)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L38-42)
```java
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L66-68)
```java
    private void action(RequestProperties filter, ContractCallRequest request) {
        switch (filter.getAction()) {
            case LOG -> log.info("{}", request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L28-29)
```java
    @Hex
    private String data;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestProperties.java (L29-60)
```java
    private ActionType action = ActionType.LOG;

    @NotNull
    private List<RequestFilter> filters = List.of();

    @PositiveOrZero
    private long limit = Long.MAX_VALUE;

    @Min(0)
    @Max(100)
    private long rate = 100;

    @Getter(lazy = true)
    private final Bucket bucket = createBucket();

    @Override
    public boolean test(ContractCallRequest contractCallRequest) {
        if (rate == 0 || counter.getAndIncrement() >= limit) {
            return false;
        }

        if (action != ActionType.THROTTLE && RandomUtils.secure().randomLong(0L, 100L) >= rate) {
            return false;
        }

        for (var filter : filters) {
            if (filter.test(contractCallRequest)) {
                return true;
            }
        }

        return filters.isEmpty();
```
