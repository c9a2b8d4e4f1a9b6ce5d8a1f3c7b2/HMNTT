### Title
Unauthenticated Distributed Flood of `getNodes()` Exhausts DB Connection Pool via Unbounded Cross-Connection Concurrency

### Summary
`NetworkController.getNodes()` accepts unauthenticated gRPC requests with no application-level rate limiting. The only concurrency guard — `maxConcurrentCallsPerConnection = 5` — is scoped per TCP connection, so an attacker opening connections from many source IPs multiplies that limit linearly. Each call drives repeated synchronous DB queries through a `boundedElastic` scheduler, and a sufficient flood exhausts the HikariCP connection pool, causing all subsequent legitimate address-book queries to queue indefinitely and time out.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) immediately subscribes a reactive pipeline with no throttle gate:

```java
// NetworkController.java lines 33-38
final var disposable = Mono.fromCallable(() -> toFilter(request))
        .flatMapMany(networkService::getNodes)
        .map(this::toNodeAddress)
        .onErrorMap(ProtoUtil::toStatusRuntimeException)
        .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

`NetworkServiceImpl.getNodes()` (lines 55–77) then executes multiple DB round-trips per call — one for `findLatestTimestamp`, one for `findAllStakeByConsensusTimestamp`, and repeated paged calls to `findByConsensusTimestampAndNodeId` (default `pageSize = 10`, `pageDelay = 250 ms`) — all scheduled on `Schedulers.boundedElastic()`.

**Root cause — failed assumption:**

The design assumes `maxConcurrentCallsPerConnection = 5` (set in `GrpcConfiguration` line 33) bounds total server load. That assumption is false: the limit is per-TCP-connection. With N distinct source IPs each opening one connection, the server accepts N × 5 fully concurrent, DB-hitting streams simultaneously. There is no global call counter, no token bucket, and no per-IP limit anywhere in the `grpc` module.

**Why existing checks fail:**

| Control | Scope | Bypass |
|---|---|---|
| `maxConcurrentCallsPerConnection = 5` | Per TCP connection | Open more connections from different IPs |
| GCP gateway `maxRatePerEndpoint: 250` | Infrastructure-optional; per backend pod, not per source IP | Not deployed by default (`global.gateway.enabled: false`); does not cap distributed multi-IP floods |
| `ThrottleConfiguration` / `ThrottleManagerImpl` | `web3` module only | Entirely absent from `grpc` module |
| No `GlobalServerInterceptor` with rate logic | — | Confirmed by grep: zero throttle interceptors in `grpc/src/main/` |

### Impact Explanation

Each concurrent `getNodes()` call holds a HikariCP connection for the duration of all paged DB reads. With the default `pageSize = 10` and a real-world address book of ~30 nodes, each call makes ≥3 DB round-trips spaced 250 ms apart, holding a connection for ~750 ms+. A flood of ~100 concurrent calls (20 IPs × 5 streams each) saturates a typical pool of 10–20 connections. Once the pool is exhausted, every new legitimate query blocks until the pool timeout fires, returning an error to the caller. The Prometheus alert `GrpcHighDatabaseConnections` fires at 75% utilization but provides no automatic back-pressure — it is observability only. The address book is the bootstrap mechanism for Hedera SDK clients; its unavailability prevents clients from discovering network nodes, constituting a network partition from the client's perspective.

### Likelihood Explanation

The endpoint is publicly documented and reachable without credentials:

```
grpcurl -plaintext -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
  <host>:5600 com.hedera.mirror.api.proto.NetworkService/getNodes
```

A single attacker with 20 cloud VMs (each with a distinct IP) can sustain the flood indefinitely at negligible cost. No authentication, no CAPTCHA, no proof-of-work is required. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Add a global gRPC server interceptor** in the `grpc` module (analogous to `web3`'s `ThrottleManagerImpl`) using Bucket4j to enforce a global requests-per-second ceiling across all connections.
2. **Add per-source-IP rate limiting** inside the interceptor using `io.grpc.Attributes` / peer address to extract the caller IP and maintain per-IP token buckets.
3. **Set a hard `maxConnectionAge`** on `NettyServerBuilder` to force connection recycling and prevent long-lived flood connections.
4. **Enforce `limit > 0`** in `AddressBookFilter` validation so unbounded streaming calls (`limit=0`) are rejected or capped server-side.
5. **Make the GCP gateway `maxRatePerEndpoint` mandatory** (not opt-in) and add a per-source-IP policy at the load-balancer layer as a defense-in-depth measure.

### Proof of Concept

```bash
# Requires grpcurl and GNU parallel
# Simulate 20 "source IPs" by opening 20 independent connections in parallel,
# each firing 5 concurrent streams (matching maxConcurrentCallsPerConnection)

flood() {
  for i in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
      <TARGET_HOST>:5600 \
      com.hedera.mirror.api.proto.NetworkService/getNodes &
  done
  wait
}
export -f flood

# Launch 20 parallel "clients" (each from a distinct cloud VM / IP in a real attack)
parallel -j 20 flood ::: $(seq 1 20)

# Expected result: HikariCP pool exhausted; legitimate getNodes() calls
# return UNAVAILABLE or hang until statement timeout (default 10 000 ms).
# Observable via: sum(hikaricp_connections_active{application="grpc"}) == pool_max
```