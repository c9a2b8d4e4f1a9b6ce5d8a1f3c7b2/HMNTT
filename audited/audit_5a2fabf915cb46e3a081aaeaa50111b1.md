### Title
Thread Pool Exhaustion via Concurrent In-Flight Request Accumulation in ThrottleManager

### Summary
`ThrottleManagerImpl.throttle()` enforces only a rate-of-arrival limit (requests/second and gas/second via token buckets) but never tracks or caps the number of simultaneously executing requests. Because each accepted request occupies a Tomcat worker thread for its full execution duration (up to the 10-second `requestTimeout`), an unprivileged attacker can saturate the thread pool by sustaining requests at the allowed rate, rendering the node unresponsive without ever exceeding the per-second admission check.

### Finding Description

**Exact code path**

`ThrottleManagerImpl.throttle()` ( [1](#0-0) ) performs two token-bucket checks at admission time:

1. `rateLimitBucket.tryConsume(1)` — rejects if more than `requestsPerSecond` (default **500**) new requests arrive in a second. [2](#0-1) 
2. `gasLimitBucket.tryConsume(scaleGas(request.getGas()))` — rejects if the declared gas would exceed `gasPerSecond` (default **7.5 × 10⁹**). [3](#0-2) 

Both buckets are **time-based** (they refill every second regardless of whether previously admitted requests have finished). Neither bucket is decremented by in-flight count; there is no semaphore, no `AtomicInteger` for active requests, and no queue-depth check anywhere in the throttle layer. [4](#0-3) 

After passing `throttle()`, the request proceeds synchronously through `contractExecutionService.processCall()` on the same Tomcat worker thread. [5](#0-4) 

The only upper bound on how long a thread can be held is `Web3Properties.requestTimeout`, which defaults to **10 seconds**. [6](#0-5) 

**Root cause and failed assumption**

The design assumes that limiting the *rate* of new requests is sufficient to bound resource consumption. This assumption fails when individual requests are long-lived: at 500 req/s with a 10-second maximum execution window, up to **5 000 requests** can be simultaneously in-flight, while Spring Boot's embedded Tomcat defaults to **200 worker threads**. The thread pool is exhausted after fewer than 0.4 seconds of sustained attack.

**Why the gas bucket does not help**

The gas bucket refills at a fixed wall-clock rate (`refillGreedy(gasLimit, Duration.ofSeconds(1))`). [7](#0-6)  `restore()` returns tokens only on `InvalidParametersException` (validation failure), not on normal completion. [8](#0-7)  Tokens therefore refill by time, not by request completion, so the bucket does not act as a concurrency semaphore.

**Network partition amplification**

During a network partition the isolated node cannot reach the consensus network or may experience elevated database latency. Requests that would normally complete in milliseconds can stall for seconds waiting on DB connection timeouts (HikariCP default: 30 s) or state-fetch timeouts. This extends per-request thread hold time well beyond the normal case, reducing the number of attacker requests needed to fill the pool.

### Impact Explanation

Once all Tomcat worker threads are occupied, the server stops accepting new connections (or queues them until `acceptCount` is exhausted). All legitimate users — including operators trying to diagnose or recover from the partition — are denied service. The node effectively becomes a black hole for the duration of the attack. Because the web3 endpoint is the primary JSON-RPC interface, this constitutes a complete denial of service of the mirror node's EVM query capability. Severity: **High**.

### Likelihood Explanation

No authentication or API key is required to call `POST /api/v1/contracts/call`. [9](#0-8)  Any internet-accessible attacker can open a small number of persistent HTTP connections and stream requests at the 500 req/s rate limit. The attack is cheap (no on-chain cost, no wallet needed), repeatable, and requires no special knowledge beyond the public API schema. The default gas value in `ContractCallRequest` is already set to the maximum (15 000 000), so no crafting is needed. [10](#0-9) 

### Recommendation

1. **Add a concurrency semaphore** in `ThrottleManagerImpl` (or as a servlet filter before the controller) using `java.util.concurrent.Semaphore` with a configurable `maxConcurrentRequests` property. Reject with HTTP 429 when the semaphore cannot be acquired immediately.
2. **Expose `maxConcurrentRequests` in `ThrottleProperties`** alongside `requestsPerSecond` so operators can tune it independently.
3. **Configure Tomcat limits explicitly**: set `server.tomcat.max-threads`, `server.tomcat.accept-count`, and `server.tomcat.connection-timeout` in application configuration rather than relying on defaults.
4. **Enforce the `requestTimeout` at the thread level** (e.g., via Spring MVC async or a `HandlerInterceptor`) so that a stalled DB call during a partition does not hold a thread beyond the configured timeout.

### Proof of Concept

```bash
# Requires: curl, GNU parallel or xargs
# No authentication needed.

TARGET="http://<mirror-node-host>/api/v1/contracts/call"
PAYLOAD='{"to":"0x0000000000000000000000000000000000000001","gas":15000000,"estimate":false}'

# Step 1: flood at rate limit with max-gas requests (each will run EVM for ~seconds)
# Send 500 req/s across 10 parallel workers for 5 seconds
seq 1 2500 | xargs -P 10 -I{} \
  curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" &

# Step 2: after ~1 second, attempt a legitimate request — expect timeout or connection refused
sleep 1
curl -v --max-time 5 -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
# Expected: connection hangs or returns 503/connection refused
# indicating thread pool exhaustion
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L20-76)
```java
final class ThrottleManagerImpl implements ThrottleManager {

    static final String REQUEST_PER_SECOND_LIMIT_EXCEEDED = "Requests per second rate limit exceeded";
    static final String GAS_PER_SECOND_LIMIT_EXCEEDED = "Gas per second rate limit exceeded.";

    @Qualifier(GAS_LIMIT_BUCKET)
    private final Bucket gasLimitBucket;

    @Qualifier(RATE_LIMIT_BUCKET)
    private final Bucket rateLimitBucket;

    @Qualifier(OPCODE_RATE_LIMIT_BUCKET)
    private final Bucket opcodeRateLimitBucket;

    private final ThrottleProperties throttleProperties;

    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }

    @Override
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }

    @Override
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
    }

    private void action(RequestProperties filter, ContractCallRequest request) {
        switch (filter.getAction()) {
            case LOG -> log.info("{}", request);
            case REJECT -> throw new ThrottleException("Invalid request");
            case THROTTLE -> {
                if (!filter.getBucket().tryConsume(1)) {
                    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
                }
            }
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L19-20)
```java
    @DurationMin(seconds = 1L)
    private Duration requestTimeout = Duration.ofSeconds(10L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L36-44)
```java
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L37-37)
```java
    private long gas = 15_000_000L;
```
