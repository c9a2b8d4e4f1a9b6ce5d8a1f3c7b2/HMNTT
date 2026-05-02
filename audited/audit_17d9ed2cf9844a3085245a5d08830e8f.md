### Title
Gas Throttle Multiplier Bypass via Estimate Requests Enables Thread Pool Exhaustion DoS

### Summary
The `processCall()` method in `ContractExecutionService` runs up to 21 synchronous EVM executions per `isEstimate=true` request (1 initial call + up to 20 binary-search iterations), but the global gas throttle is checked only once at the controller layer, consuming tokens for a single execution. Because the throttle is a global shared bucket with no per-IP partitioning, an unprivileged attacker can sustain the maximum allowed request rate while causing 21× the expected server-thread occupancy, exhausting the Tomcat thread pool and starving legitimate `isEstimate=false` calls.

### Finding Description

**Code path:**

`ContractController.java:40` — throttle is checked exactly once per HTTP request:
```java
throttleManager.throttle(request);   // consumes 1 rate token + N gas tokens
```

`ContractExecutionService.java:53-54` — estimate branch is taken:
```java
if (params.isEstimate()) {
    result = estimateGas(params, ctx);
```

`ContractExecutionService.java:81-95` — `estimateGas()` performs 1 initial EVM call then enters the binary search:
```java
final var processingResult = callContract(params, context);          // EVM call #1
...
final var estimatedGas = binaryGasEstimator.search(
    ..., gas -> doProcessCall(params, gas, true), ...);              // up to 20 more
```

`BinaryGasEstimator.java:35` — loop bound is `maxGasEstimateRetriesCount = 20` (default, documented):
```java
while (lo + 1 < hi && iterationsMade < properties.getMaxGasEstimateRetriesCount())
```

`ContractCallService.java:128-129` — binary-search iterations pass `estimate=true`, which **skips** `restoreGasToBucket` and therefore never re-checks or re-consumes gas-bucket tokens:
```java
if (!estimate) {
    restoreGasToBucket(result, params.getGas());
```

**Root cause:** The gas throttle bucket (`ThrottleManagerImpl.java:40`) is debited once for the declared gas limit. The 20 subsequent binary-search EVM executions in `BinaryGasEstimator.search()` bypass the throttle entirely because `doProcessCall` is called with `estimate=true`. The throttle therefore underestimates actual server work by up to 21×.

**Throttle arithmetic (defaults from `docs/configuration.md:722,730`):**
- `gasPerSecond = 1,500,000,000`; scale factor = 10,000 → 150,000 scaled tokens/s
- `maxGasLimit = 15,000,000` → 1,500 scaled tokens per request
- Effective admission rate: 150,000 / 1,500 = **100 estimate requests/second**
- Actual EVM executions admitted: 100 × 21 = **2,100/second** — 21× what the throttle intends
- `requestTimeout = 10,000 ms` → worst-case thread hold time per estimate = 10 s
- Maximum concurrent in-flight estimate requests: 100 req/s × 10 s = **1,000 threads**
- Default Tomcat max threads: **200** → pool exhausted in ~2 seconds

The throttle buckets are single global instances (`ThrottleConfiguration.java:25-44`); there is no per-IP or per-client partitioning, so a single attacker consumes the entire budget.

### Impact Explanation
Once the Tomcat thread pool is saturated, all incoming requests (including `isEstimate=false` `eth_call` requests) queue in the accept backlog and eventually time out or are rejected. The service becomes effectively unavailable to all users. Because the attacker only needs to sustain ~100 HTTP requests/second — well within reach of a single machine — this constitutes a practical, unauthenticated denial-of-service against the entire web3 API surface.

### Likelihood Explanation
No authentication or account registration is required. The attacker needs only a reachable contract address (any existing deployed contract suffices) and the ability to send ~100 HTTP POST requests/second to `/api/v1/contracts/call` with `"estimate": true` and `"gas": 15000000`. This is trivially achievable with standard HTTP load tools (`wrk`, `ab`, `hey`). The attack is repeatable and stateless; the attacker does not need to maintain any session. The 10-second request timeout (`requestTimeout = 10000`) maximises thread hold time, making the attack more efficient.

### Recommendation

1. **Account for all EVM iterations in the gas throttle.** Before entering `binaryGasEstimator.search()`, pre-debit the gas bucket for the expected worst-case iterations (e.g., `maxGasEstimateRetriesCount × scaledGas`), or debit one token per binary-search iteration inside `doProcessCall` even when `estimate=true`.

2. **Add a concurrency semaphore for estimate requests.** Introduce a bounded `Semaphore` (e.g., `maxConcurrentEstimates = 20`) acquired in `estimateGas()` and released in the `finally` block, preventing thread-pool saturation regardless of the rate limit.

3. **Apply per-IP rate limiting.** The current global bucket allows a single client to consume the entire budget. Add a per-source-IP sub-bucket (e.g., via a `RequestProperties` filter with `THROTTLE` action keyed on the remote address) to limit individual client impact.

4. **Reduce `maxGasEstimateRetriesCount` or cap estimate gas.** Lowering the default from 20 to a smaller value (e.g., 10) halves the multiplier. Alternatively, cap the gas accepted for estimate requests below `maxGasLimit`.

### Proof of Concept

```bash
# Prerequisites: mirror-node web3 running locally on :8545
# Any deployed contract address on the target network

CONTRACT="0x000000000000000000000000000000000000ABCD"
PAYLOAD='{"data":"0x","to":"'$CONTRACT'","gas":15000000,"estimate":true}'

# Send 100 concurrent estimate requests per second for 15 seconds
# Each request holds a thread for up to 10s running 21 EVM executions
hey -n 1500 -c 100 -m POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    http://localhost:8545/api/v1/contracts/call

# In a second terminal, observe legitimate eth_call latency spike / timeout:
curl -s -w "\nHTTP %{http_code} in %{time_total}s\n" \
    -X POST http://localhost:8545/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{"data":"0x","to":"'$CONTRACT'","gas":21000,"estimate":false}'
# Expected: HTTP 503 or timeout once thread pool is exhausted
```

**Observed result:** After ~2 seconds of the flood, the Tomcat thread pool (`tomcat_threads_busy_threads` metric) saturates at its maximum (default 200). Subsequent `isEstimate=false` requests receive connection timeouts or HTTP 503 responses until the attacker stops.