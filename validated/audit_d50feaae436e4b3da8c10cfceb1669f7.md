All cited code references have been verified against the repository. Here is the result:

---

Audit Report

## Title
Global-Only Rate Limit Bucket Enables Single-Client DoS Starvation of Web3 API

## Summary
`ThrottleConfiguration.rateLimitBucket()` creates a single application-wide `Bucket` bean shared by every caller. No per-IP or per-client sub-limit exists at the application layer or in any of the deployed infrastructure configurations. A single unprivileged attacker can saturate the entire 500 RPS budget, causing HTTP 429 responses for all other clients for the duration of the attack.

## Finding Description

**`ThrottleConfiguration.rateLimitBucket()` (lines 24–32):** Constructs one singleton `Bucket` with `capacity = requestsPerSecond` (default 500) and `refillGreedy(rateLimit, Duration.ofSeconds(1))`. This bean is application-scoped with no per-caller partitioning. [1](#0-0) 

**`ThrottleManagerImpl.throttle()` (line 38):** Calls `rateLimitBucket.tryConsume(1)` against that single shared bean for every inbound request. No caller identity (IP, account, session) is consulted. [2](#0-1) 

**Default `requestsPerSecond = 500` confirmed in `ThrottleProperties` (line 35):** [3](#0-2) 

**Why existing checks fail:**

- `ThrottleProperties.request` defaults to `List.of()`, so `RequestProperties` per-request filters are entirely disabled out of the box. Even when enabled, they match on request payload fields (`DATA`, `FROM`, `TO`, `GAS`, etc.), not on source IP. [4](#0-3) 

- `LoggingFilter` reads `request.getRemoteAddr()` only to populate a log line — it is never passed to any throttle decision path. [5](#0-4) 

- The Traefik ingress middleware is configured exclusively for `retry` (3 attempts, 100 ms interval). No `rateLimit` middleware is present. [6](#0-5) 

- The GCP backend policy `maxRatePerEndpoint: 250` is a per-pod throughput cap, not a per-client cap. It limits total pod load, not individual client share. [7](#0-6) 

## Impact Explanation
Any client that exhausts the 500-token bucket within a one-second window causes every subsequent request from every other client to receive HTTP 429 `"Requests per second rate limit exceeded"` for the remainder of that window. The `/api/v1/contracts/call` endpoint is the sole EVM-level path for staking-reward precompile queries in this service. Continuous flooding renders the endpoint unavailable to all legitimate users for the duration of the attack. There is no direct fund loss, but inability to query `pending_reward` balances can delay reward collection decisions. **Severity: Medium** (availability impact only).

## Likelihood Explanation
No special privilege, on-chain asset, or account is required. A single machine running a standard HTTP flood tool (`wrk`, `hey`, `ab`) can trivially sustain ≥500 POST requests/second. The attack is repeatable indefinitely, costs the attacker nothing beyond bandwidth, and is not detectable until monitoring alerts fire. **Likelihood: High**.

## Recommendation

1. **Application layer — per-IP bucket map:** Replace the single `Bucket` bean with a `LoadingCache<String, Bucket>` (e.g., Caffeine) keyed by client IP (extracted from `X-Forwarded-For` or `RemoteAddr`). Each IP gets its own bucket with a per-IP cap (e.g., 10–50 RPS), while the global bucket remains as a secondary ceiling.

2. **Infrastructure layer — Traefik `rateLimit` middleware:** Add a `rateLimit` entry alongside the existing `retry` middleware in `charts/hedera-mirror-web3/values.yaml`, using `sourceCriterion: ipStrategy` to enforce per-IP limits at the ingress before requests reach the application. [6](#0-5) 

3. **nginx (docker-compose):** Add a `limit_req_zone` and `limit_req` directive scoped to the `/api/v1/contracts/call` location block.

## Proof of Concept

```bash
# Flood the endpoint at 600 RPS from a single machine
wrk -t4 -c50 -d30s -s post.lua \
    https://<mirror-node-host>/api/v1/contracts/call

# post.lua:
# wrk.method = "POST"
# wrk.headers["Content-Type"] = "application/json"
# wrk.body = '{"data":"0x","to":"0x0000000000000000000000000000000000000167","gas":21000}'
```

Within the first second, the attacker's 600 concurrent requests drain all 500 tokens. All subsequent requests from any other client receive:

```json
HTTP/1.1 429 Too Many Requests
{"_status":{"messages":[{"message":"Requests per second rate limit exceeded"}]}}
```

This repeats every second for as long as the flood continues, with zero attacker cost beyond network bandwidth.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L31-32)
```java
    @NotNull
    private List<RequestProperties> request = List.of();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/LoggingFilter.java (L68-69)
```java
        var params =
                new Object[] {request.getRemoteAddr(), request.getMethod(), uri, elapsed, status, message, content};
```

**File:** charts/hedera-mirror-web3/values.yaml (L56-56)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** charts/hedera-mirror-web3/values.yaml (L157-160)
```yaml
middleware:
  - retry:
      attempts: 3
      initialInterval: 100ms
```
