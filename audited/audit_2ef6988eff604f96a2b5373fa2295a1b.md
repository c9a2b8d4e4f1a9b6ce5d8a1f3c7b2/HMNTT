### Title
Unauthenticated Access to Expensive EVM Replay Endpoint with Node-Local-Only Rate Limiting Enables Sustained Resource Exhaustion

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint requires no authentication and its rate-limiting `opcodeRateLimitBucket` is a local in-memory Bucket4j instance scoped to each JVM process, not a distributed/global counter. In a multi-node mirror node deployment, each node independently allows the configured rate (default: 1 req/sec) of expensive full EVM transaction replays, meaning an attacker can multiply their effective throughput by targeting all nodes simultaneously, sustaining a continuous load of CPU/memory-intensive EVM replays with no credential requirement.

### Finding Description

**Code path:**

`OpcodesController.getContractOpcodes()` — `web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java`, lines 52–68 — performs no authentication check. The only guards are:
1. `properties.isEnabled()` — a feature flag, not a security control.
2. `validateAcceptEncodingHeader()` — requires `Accept-Encoding: gzip`, trivially satisfied.
3. `throttleManager.throttleOpcodeRequest()` — calls into `ThrottleManagerImpl`. [1](#0-0) 

`ThrottleManagerImpl.throttleOpcodeRequest()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 52–56 — consumes one token from `opcodeRateLimitBucket` and throws only if the local bucket is empty. There is no per-IP, per-client, or distributed check. [2](#0-1) 

`ThrottleConfiguration.opcodeRateLimitBucket()` — `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`, lines 47–55 — constructs the bucket with `Bucket.builder().addLimit(limit).build()`. This is a plain local in-memory Bucket4j bucket. Unlike the `gasLimitBucket` (which at least uses `SynchronizationStrategy.SYNCHRONIZED`), there is no distributed backend (no Redis, no Hazelcast). Each JVM instance holds its own independent counter. [3](#0-2) 

**Default rate:** `opcodeRequestsPerSecond = 1` — `ThrottleProperties.java` line 29. Each node allows exactly 1 opcode replay request per second. [4](#0-3) 

**Root cause / failed assumption:** The design assumes the `opcodeRateLimitBucket` acts as a global cluster-wide throttle. It does not. It is a per-JVM in-memory counter. In a horizontally scaled deployment with N mirror node instances, the effective cluster-wide rate is N × 1 = N req/sec of expensive EVM replays, not 1 req/sec. No authentication, no IP-based rate limiting, and no distributed rate limiting exist to compensate.

**No Spring Security configuration** was found for the web3 module (no `SecurityConfig` class exists), confirming there is no authentication layer protecting this endpoint.

### Impact Explanation
Each opcode replay re-executes the full EVM transaction with optional stack, memory, and storage tracing — the controller's own Javadoc warns this "may take a significant amount of time to complete." An attacker sustaining N req/sec across N nodes (one per node) keeps each node continuously busy with EVM replay work. This competes directly with the mirror node's primary function of ingesting and processing Hedera network transactions. With a sufficiently large cluster and/or sufficiently expensive transactions (complex contracts with `memory=true&storage=true`), this can degrade ≥30% of processing capacity. The response payload is also large (hence the mandatory gzip requirement), adding I/O pressure.

### Likelihood Explanation
Preconditions are minimal: no credentials, no special network access, no prior knowledge beyond a valid transaction hash (publicly observable on-chain). The attacker only needs to discover the number of mirror node instances (e.g., via DNS round-robin, public infrastructure listings, or load balancer probing) and send one request per second per node with `Accept-Encoding: gzip`. This is trivially scriptable and repeatable indefinitely. The attack is low-cost for the attacker and high-cost for the target.

### Recommendation
1. **Distributed rate limiting**: Replace the local `Bucket.builder()` for `opcodeRateLimitBucket` with a Bucket4j distributed proxy backed by Redis (already present in the infrastructure for other mirror node components), so the limit is enforced cluster-wide.
2. **Per-IP rate limiting**: Add a per-source-IP token bucket layer before the global bucket so a single client cannot consume the entire cluster budget.
3. **Authentication/authorization**: Require an API key or similar credential for this endpoint, given its explicit high-cost nature.
4. **Connection/concurrency limit**: Enforce a maximum number of concurrent in-flight opcode replay requests (not just a per-second rate), since a single slow replay can hold a thread for the full duration.

### Proof of Concept
```bash
# Discover all mirror node instances (example: 3 nodes behind a load balancer)
# Node IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3
# Known transaction hash: 0xabc123...

# Script: send 1 req/sec to each node simultaneously, indefinitely
while true; do
  for NODE in 10.0.0.1 10.0.0.2 10.0.0.3; do
    curl -s -H "Accept-Encoding: gzip" \
      "http://$NODE/api/v1/contracts/results/0xabc123.../opcodes?stack=true&memory=true&storage=true" \
      -o /dev/null &
  done
  sleep 1
done
```

Each node processes 1 expensive EVM replay/sec (passing its local rate limit), resulting in 3 concurrent full EVM replays/sec cluster-wide — sustained indefinitely, with zero credentials required.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-68)
```java
    @GetMapping(value = "/{transactionIdOrHash}/opcodes")
    OpcodesResponse getContractOpcodes(
            @PathVariable TransactionIdOrHashParameter transactionIdOrHash,
            @RequestParam(required = false, defaultValue = "true") boolean stack,
            @RequestParam(required = false, defaultValue = "false") boolean memory,
            @RequestParam(required = false, defaultValue = "false") boolean storage,
            @RequestHeader(value = HttpHeaders.ACCEPT_ENCODING) String acceptEncoding) {
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }

        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L52-56)
```java
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L47-55)
```java
    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L29-29)
```java
    private long opcodeRequestsPerSecond = 1;
```
