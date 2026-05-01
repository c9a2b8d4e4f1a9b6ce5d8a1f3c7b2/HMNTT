### Title
Unbounded Blocking JDBC Execution on `Schedulers.boundedElastic()` in `getNodes()` Enables Unauthenticated Thread-Pool Exhaustion DoS

### Summary
`NetworkController.getNodes()` accepts unauthenticated gRPC calls with no application-level rate limit or concurrency cap. Each call drives `NetworkServiceImpl.getNodes()`, which executes multiple synchronous blocking JDBC calls directly on the Spring task executor thread and then schedules subsequent paged DB queries on `Schedulers.boundedElastic()` threads via `transactionOperations.execute()`. An attacker opening many connections and flooding concurrent `getNodes()` requests can exhaust both the Spring task executor and the `boundedElastic()` thread pool, starving all reactive pipelines that depend on those schedulers and rendering the gRPC service unresponsive.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) subscribes to `networkService::getNodes` with no rate limiting, no bulkhead, and no circuit breaker at the application layer:

```java
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(networkService::getNodes)   // no concurrency guard
        .map(this::toNodeAddress)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(...);
```

`NetworkServiceImpl.getNodes()` (lines 55–77) immediately makes **three synchronous blocking JDBC calls** on the calling thread (the Spring `applicationTaskExecutor` thread that the gRPC server uses, configured at `GrpcConfiguration.java` line 32):

```java
long addressBookTimestamp = addressBookRepository.findLatestTimestamp(fileId.getId())...;   // blocking
long nodeStakeTimestamp   = nodeStakeRepository.findLatestTimestamp()...;                   // blocking
var  nodeStakeMap         = nodeStakeRepository.findAllStakeByConsensusTimestamp(...);       // blocking
```

Then the paged Flux is constructed with `Schedulers.boundedElastic()` as the repeat scheduler (line 72):

```java
return Flux.defer(() -> page(context))
        .repeatWhen(RepeatSpec.create(...)
                .withFixedDelay(addressBookProperties.getPageDelay())
                .withScheduler(Schedulers.boundedElastic()));   // each repeat fires on boundedElastic
```

`page()` (lines 79–108) calls `transactionOperations.execute()` — a synchronous Spring `TransactionTemplate` that performs blocking JDBC — on whichever thread the `repeatWhen` scheduler dispatches to, i.e., a `boundedElastic()` thread:

```java
private Flux<AddressBookEntry> page(AddressBookContext context) {
    return transactionOperations.execute(t -> {          // BLOCKING JDBC on boundedElastic thread
        var nodes = addressBookEntryRepository
                .findByConsensusTimestampAndNodeId(...);  // synchronous DB query
        ...
        return Flux.fromIterable(nodes);
    });
}
```

**Root cause:** Blocking JDBC work is placed directly on `Schedulers.boundedElastic()` threads (and the Spring task executor) with no upper bound on how many concurrent `getNodes()` calls can be in flight simultaneously. The failed assumption is that infrastructure-level guards (Traefik, GCP gateway) are always present and sufficient to prevent thread-pool exhaustion.

**Why existing checks fail:**

| Check | Why insufficient |
|---|---|
| `maxConcurrentCallsPerConnection = 5` (`NettyProperties.java` line 14) | Per-connection only; attacker opens N connections → 5N concurrent calls |
| Traefik circuit breaker (`values.yaml` line 157–158): `NetworkErrorRatio() > 0.10` | Triggers on errors, not on slow/blocking responses; slow DB queries don't error until `statementTimeout` (10 s) |
| GCP gateway `maxRatePerEndpoint: 250` (`values.yaml` line 69) | Optional infrastructure, not always deployed; even at 250 req/s, 250 concurrent slow-blocking threads are enough to exhaust the pool |
| `db.statementTimeout = 10000` (10 s) | Limits per-query duration but does not prevent thread exhaustion; each thread blocks for the full 10 s before releasing |
| No application-level throttle in the `grpc` module | The `ThrottleConfiguration`/`ThrottleManagerImpl` exist only in the `web3` module; the gRPC module has no equivalent |

### Impact Explanation
`Schedulers.boundedElastic()` defaults to `10 × Runtime.availableProcessors()` threads (e.g., 40 threads on a 4-core pod). With `db.statementTimeout = 10 s`, each blocked thread holds for up to 10 seconds. An attacker maintaining 40+ concurrent `getNodes()` requests with a degraded DB (which the flood itself induces) exhausts the pool. Once exhausted, the `repeatWhen` scheduler cannot dispatch further pages, backpressure propagates upstream, and the Spring task executor (shared with the gRPC server) also saturates from the initial three blocking calls per request. The result is that all gRPC calls — including `ConsensusService.subscribeTopic` — become unresponsive. The mirror node's gRPC service is effectively taken offline for all consumers (wallets, SDKs, dApps) that rely on it for address book and topic subscription data.

### Likelihood Explanation
The gRPC port (5600) is publicly exposed with no authentication. Opening multiple TCP connections and sending concurrent `getNodes()` requests requires only a standard gRPC client (e.g., `grpcurl`, any SDK). The attack is self-reinforcing: more concurrent requests increase DB load, which slows queries, which extends thread-blocking duration, which requires fewer concurrent requests to maintain exhaustion. A single attacker with a modest number of connections (e.g., 10 connections × 5 calls = 50 concurrent requests on a 4-core pod) is sufficient. The attack is repeatable and requires no special privileges or knowledge beyond the public proto definition.

### Recommendation
1. **Add a global concurrency semaphore** in `NetworkController.getNodes()` using Reactor's `flatMap(maxConcurrency)` or a `Semaphore`/`Bulkhead` (Resilience4j) to cap total in-flight `getNodes()` calls server-wide (e.g., 20).
2. **Move blocking JDBC off `boundedElastic()`**: wrap `page()` with `.subscribeOn(Schedulers.boundedElastic())` explicitly and use a dedicated, bounded scheduler for DB work rather than the shared default.
3. **Add application-level rate limiting** to the gRPC module analogous to the `ThrottleManagerImpl` in `web3`, keyed on client IP or connection identity.
4. **Set a global `maxConnectionAge`** on the Netty server builder to recycle connections and limit long-lived flooding connections.
5. **Add a global `maxConcurrentCalls`** (not just per-connection) via `NettyServerBuilder.maxConcurrentCallsPerConnection` combined with a total-call interceptor.

### Proof of Concept

```bash
# Prerequisites: grpcurl installed, mirror node gRPC on localhost:5600

# Open 10 parallel shells, each sending 5 concurrent getNodes calls (50 total)
for i in $(seq 1 50); do
  grpcurl -plaintext \
    -d '{"file_id": {"fileNum": 102}}' \
    localhost:5600 \
    com.hedera.mirror.api.proto.NetworkService/getNodes &
done
wait

# With a degraded or loaded DB, each call blocks a boundedElastic() thread for
# up to db.statementTimeout (10 s). On a 4-core pod (40 boundedElastic threads),
# 50 concurrent calls saturate the pool. Subsequent legitimate gRPC calls
# (e.g., subscribeTopic) will queue indefinitely or be rejected.
# Observable symptom: all gRPC calls hang; liveness probe at /actuator/health/liveness
# may still pass (HTTP, separate thread pool) while gRPC is fully unresponsive.
```