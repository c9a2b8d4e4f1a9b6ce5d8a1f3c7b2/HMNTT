### Title
Global Shared `rateLimitBucket` Allows Unprivileged Attacker to DoS All Web3 Smart Contract Calls

### Summary
The `rateLimitBucket` in `ThrottleConfiguration.java` is a single application-wide token bucket with no per-IP or per-user isolation. Any unauthenticated caller can exhaust all 500 tokens per second by sending cheap requests (gas ≤ 10,000), which bypass the gas bucket entirely, causing every subsequent legitimate `eth_call` or contract simulation to receive a `ThrottleException` for the remainder of that second.

### Finding Description

**Code path:**

`ThrottleConfiguration.rateLimitBucket()` (lines 24–32) creates one global `Bucket` with capacity = `requestsPerSecond` (default 500), refilled greedily every second, with no `SynchronizationStrategy` (unlike `gasLimitBucket`): [1](#0-0) 

`ThrottleManagerImpl.throttle()` (lines 37–42) calls `rateLimitBucket.tryConsume(1)` for every incoming request, regardless of caller identity: [2](#0-1) 

**Gas-bucket bypass:** `ThrottleProperties.scaleGas()` returns `0` for any `gas ≤ 10,000`, and `tryConsume(0)` always succeeds: [3](#0-2) 

This means an attacker can craft requests with `gas=0` (or any value ≤ 10,000) that consume **1 rate-limit token** but **0 gas tokens**, making exhaustion of the rate bucket maximally cheap.

**Root cause:** The failed assumption is that a global request-count limit is sufficient to prevent one client from starving all others. There is no per-source-IP, per-session, or per-authenticated-user sub-bucket.

**Why existing checks fail:**
- The `gasLimitBucket` check (line 40) is bypassed entirely when `gas ≤ 10,000`.
- The `RequestProperties` filter chain (lines 44–48) only applies optional LOG/REJECT/THROTTLE actions on matched patterns; it does not enforce per-caller fairness.
- No IP-based filter or middleware is present in the web3 config layer (`LoggingFilter`, `MetricsFilter`, `HibernateConfiguration`, `JacksonConfiguration` — none perform per-IP rate limiting).


### Impact Explanation
An attacker who exhausts the global `rateLimitBucket` causes every other user's `eth_call`, `eth_estimateGas`, or contract-simulation request to throw `ThrottleException("Requests per second rate limit exceeded")` for the duration of that second window. DApps and tooling relying on the mirror node's web3 API for contract state queries or gas estimation will receive errors, producing unintended smart contract behavior (failed simulations, incorrect gas estimates, broken read-only contract interactions) with no funds directly at risk. The attack is repeatable every second as long as the attacker sustains the request rate. [4](#0-3) 

### Likelihood Explanation
No privileges, authentication, or special network position are required. A single machine with a standard HTTP client can sustain 500 req/s against a public JSON-RPC endpoint. The default `requestsPerSecond = 500` is low enough to be saturated by a single-threaded loop on commodity hardware. The attack is trivially repeatable and requires no prior knowledge beyond the public endpoint URL. [5](#0-4) 

### Recommendation
1. **Per-IP sub-buckets:** Replace (or supplement) the global bucket with a `ConcurrentHashMap<String, Bucket>` keyed on the client IP (extracted from `X-Forwarded-For` or `RemoteAddr`), so one source cannot starve others.
2. **Minimum gas enforcement:** Reject or ignore requests with `gas < 21,000` (the EVM minimum) before the rate-limit check, preventing zero-cost token exhaustion.
3. **Synchronization strategy:** Apply `SynchronizationStrategy.SYNCHRONIZED` (or `LOCK_FREE`) to `rateLimitBucket` consistently with `gasLimitBucket` to avoid over-consumption under concurrent load.
4. **Infrastructure layer:** Deploy a WAF or API gateway with per-IP rate limiting in front of the web3 endpoint as a defense-in-depth measure.

### Proof of Concept
```bash
# Exhaust the global rateLimitBucket (500 req/s) with zero-gas requests
# All other users will receive HTTP 429 / ThrottleException for the remainder of each second

for i in $(seq 1 600); do
  curl -s -X POST https://<mirror-node-web3-host>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{"data":"0x","to":"0x0000000000000000000000000000000000000001","gas":0,"estimate":false,"block":"latest"}' \
    &
done
wait

# Legitimate user request issued concurrently will receive:
# {"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

Preconditions: network access to the web3 endpoint, no credentials needed.
Trigger: sustain ≥ 500 concurrent/sequential requests per second with `gas ≤ 10000`.
Result: all other callers receive `ThrottleException` for that second; attack repeats indefinitely.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L22-23)
```java
    static final String REQUEST_PER_SECOND_LIMIT_EXCEEDED = "Requests per second rate limit exceeded";
    static final String GAS_PER_SECOND_LIMIT_EXCEEDED = "Gas per second rate limit exceeded.";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```
