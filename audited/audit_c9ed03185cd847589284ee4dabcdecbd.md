### Title
Synchronous EVM Execution in `ContractController.call()` Enables Thread Pool Exhaustion DoS via Rate-Limit/Concurrency-Limit Mismatch

### Summary
The `call()` endpoint in `ContractController` dispatches EVM execution synchronously on the HTTP worker thread with no concurrency cap. The existing `ThrottleManager` is a **rate limiter** (requests per second), not a **concurrency limiter**, so an attacker sending requests at exactly the permitted rate can accumulate far more concurrent blocked threads than the Tomcat thread pool supports. The only timeout mechanism fires only at SQL statement boundaries and does not interrupt CPU-bound EVM computation, leaving threads pinned for the full execution window.

### Finding Description

**Exact code path:**

`ContractController.call()` (lines 38–51) executes synchronously:
```
throttleManager.throttle(request);   // line 40 – rate check only, returns immediately
...
final var result = contractExecutionService.processCall(params);  // line 44 – BLOCKS thread
return new ContractCallResponse(result);
```

`ThrottleManagerImpl.throttle()` (lines 37–48) uses `tryConsume()` — a non-blocking token-bucket check. It enforces **throughput** (tokens/second), not **concurrency** (simultaneous in-flight requests). Default: `requestsPerSecond = 500`, `gasPerSecond = 7,500,000,000`.

`ContractExecutionService.processCall()` (lines 44–68) runs the full EVM inside `ContractCallContext.run()` synchronously. For `isEstimate=true`, it additionally runs a binary-search loop (`binaryGasEstimator.search()`, lines 91–95) that can invoke `doProcessCall()` up to `maxGasEstimateRetriesCount = 20` times.

The only timeout is in `HibernateConfiguration.statementInspector()` (lines 31–46): it checks elapsed time **only before each SQL statement**. Pure CPU-bound EVM loops (e.g., tight arithmetic loops in bytecode) never trigger a SQL statement and therefore never hit this timeout. Default `requestTimeout = 10s`.

No `server.tomcat.max-threads` override exists in the web3 resources directory; Spring Boot defaults to **200 Tomcat worker threads**.

**Root cause:** The throttle is a rate gate, not a concurrency gate. Concurrent threads = rate × per-request execution time. At 500 req/s with 1-second average EVM execution, 500 threads are needed simultaneously — already 2.5× the default pool. At the 10-second timeout ceiling, 5,000 threads would be needed.

**Why existing checks fail:**
- `rateLimitBucket.tryConsume(1)` — only prevents >500 new requests/second from being accepted; does nothing about threads already blocked inside `processCall()`.
- `gasLimitBucket.tryConsume(...)` — limits total gas throughput, not thread occupancy.
- `statementInspector` timeout — only fires at JPA/Hibernate SQL boundaries; bypassed by EVM bytecode that loops without storage reads.
- `validateContractMaxGasLimit` — caps gas at 15M per request but does not bound execution time.

### Impact Explanation
Once the 200-thread pool is saturated, Tomcat queues incoming connections up to `server.tomcat.accept-count` (default 100) and then drops them with connection-refused errors. All `/api/v1/contracts/call` traffic on the targeted node is blocked. Because mirror node deployments typically run a small number of replicas (the Helm chart shows HPA-controlled scaling with modest resource limits: 2 CPU / 2 GiB), exhausting one pod's thread pool with a sustained ~200–500 req/s attack is sufficient to take that pod out of service. If the deployment runs 2–3 replicas, a single attacker targeting one pod removes ≥33% of processing capacity without touching consensus nodes.

### Likelihood Explanation
No authentication or API key is required to call `/api/v1/contracts/call`. The endpoint is publicly documented and reachable from any internet host. The attacker needs only to:
1. Know the public mirror node URL (publicly listed for mainnet/testnet).
2. Send HTTP POST requests at ≤500 req/s (within the rate limit) with `estimate=true` and `gas=15000000` targeting a contract with a compute-heavy loop.

This is achievable from a single machine with standard HTTP tooling (e.g., `wrk`, `hey`, `ab`). The attack is repeatable and requires no privileged access, no tokens, and no on-chain state.

### Recommendation
1. **Add a concurrency limiter** (e.g., a `Semaphore` or Resilience4j `Bulkhead`) in `ContractController.call()` or `ContractExecutionService.processCall()` that caps simultaneous in-flight EVM executions independently of the per-second rate.
2. **Enforce a wall-clock timeout on EVM execution itself**, not just at SQL boundaries. Use a `Future`/`ExecutorService` with a hard deadline, or interrupt the EVM thread after `requestTimeout` ms regardless of whether a SQL statement is pending.
3. **Configure `server.tomcat.max-threads`** explicitly and size it relative to the concurrency limit above, so thread exhaustion is bounded by design.
4. **For `estimate=true` paths**, apply a tighter concurrency cap given the binary-search loop multiplies EVM invocations up to 20×.

### Proof of Concept
```bash
# Craft a request at max gas with estimate=true (triggers binary-search loop, up to 20x EVM calls)
PAYLOAD='{"to":"0x<deployed_compute_heavy_contract>","gas":15000000,"estimate":true,"data":"0x<loop_opcode_payload>"}'

# Send 500 concurrent requests/second (within rate limit) from multiple connections
# using wrk with a Lua script or hey:
hey -n 10000 -c 500 -q 500 \
    -m POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    https://<mirror-node-host>/api/v1/contracts/call

# Expected result after ~0.4s:
# - Tomcat thread pool (200 threads) fully occupied
# - New requests receive HTTP 503 or TCP connection refused
# - Node stops serving all /contracts/call traffic until in-flight requests drain
```