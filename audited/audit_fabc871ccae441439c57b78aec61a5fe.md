### Title
Unauthenticated Rate-Limit-Free `getNodes()` gRPC Endpoint Enables DB Connection Pool Exhaustion via Uncached Timestamp Queries

### Summary
The `getNodes()` endpoint in `NetworkController` accepts requests from any unauthenticated caller with no rate limiting. Every invocation unconditionally executes two uncached database queries — `addressBookRepository.findLatestTimestamp()` and `nodeStakeRepository.findLatestTimestamp()` — against the gRPC module's shared HikariCP connection pool. An attacker opening many parallel gRPC connections and flooding the endpoint can exhaust the pool, denying legitimate clients the ability to retrieve address book data needed to discover consensus nodes for transaction gossip.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) delegates directly to `networkService::getNodes` with no authentication, no token check, and no rate-limiting interceptor:

```java
// NetworkController.java:33-38
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(networkService::getNodes)
            ...
```

`NetworkServiceImpl.getNodes()` (lines 61–64) then fires two uncached SQL queries on every single invocation:

```java
// NetworkServiceImpl.java:61-64
long addressBookTimestamp = addressBookRepository
        .findLatestTimestamp(fileId.getId())          // SELECT MAX(...) FROM address_book WHERE file_id = ?
        .orElseThrow(...);
long nodeStakeTimestamp = nodeStakeRepository.findLatestTimestamp()  // SELECT MAX(...) FROM node_stake
        .orElse(NODE_STAKE_EMPTY_TABLE_TIMESTAMP);
```

**Root cause — failed assumptions:**

1. `AddressBookRepository.findLatestTimestamp()` carries **no `@Cacheable` annotation** — it hits the database on every call.
2. `NodeStakeRepository.findLatestTimestamp()` is likewise **not cached** (only `findAllStakeByConsensusTimestamp` is `@Cacheable`).
3. The only gRPC-layer interceptor is `GrpcInterceptor`, which only sets an `EndpointContext` and passes the call through — **no rate limiting, no throttling, no auth**.
4. The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives entirely in the `web3` module and is **never wired into the gRPC module**.
5. `maxConcurrentCallsPerConnection = 5` (default) limits concurrency **per connection**, not globally. There is no cap on the number of simultaneous connections.

### Impact Explanation

Each `getNodes()` call consumes at least one HikariCP connection for the duration of the two `MAX()` queries. Under a burst from many parallel connections the pool saturates. Once exhausted:
- All subsequent gRPC calls (including legitimate address book queries) block waiting for a connection or fail with a pool-timeout error.
- Clients that rely on `getNodes()` to discover consensus node endpoints cannot obtain the address book, preventing them from routing and gossiping transactions to the network.
- The gRPC service becomes entirely unresponsive for the duration of the attack, which requires no special tooling — standard gRPC client libraries suffice.

Severity: **High** (availability impact on a public, unauthenticated, infrastructure-critical endpoint).

### Likelihood Explanation

- No credentials, tokens, or prior knowledge are required.
- The gRPC port (default 5600) is publicly reachable.
- A single attacker machine can open hundreds of TCP connections and issue concurrent `getNodes()` RPCs using any gRPC client (e.g., `grpcurl`, the Hedera Java SDK, or a trivial Go/Python script).
- The attack is repeatable and stateless — each request is independent.
- `maxConcurrentCallsPerConnection = 5` is trivially bypassed by opening more connections.

### Recommendation

1. **Cache `findLatestTimestamp()` results** in both `AddressBookRepository` and `NodeStakeRepository` with a short TTL (e.g., 2–5 s), matching the existing `cacheExpiry` pattern already used for `findAllStakeByConsensusTimestamp`.
2. **Add a gRPC-layer rate limiter** — implement a `@GlobalServerInterceptor` (alongside the existing `GrpcInterceptor`) that uses a token-bucket (e.g., Bucket4j, already a dependency in the web3 module) to cap total `getNodes()` calls per second globally and/or per source IP.
3. **Limit total inbound connections** via Netty's `maxConnectionAge` / `maxConnectionIdle` and a global `maxConcurrentCalls` (not just per-connection) in `GrpcConfiguration`.
4. **Set a HikariCP `connectionTimeout`** short enough to fail fast and return an error to the caller rather than queuing indefinitely.

### Proof of Concept

```bash
# Open 50 parallel connections, each issuing getNodes() in a tight loop
# Requires grpcurl and a valid file_id (0.0.102 is always valid)
for i in $(seq 1 50); do
  while true; do
    grpcurl -plaintext \
      -d '{"file_id": {"fileNum": 102}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.NetworkService/getNodes \
      > /dev/null 2>&1
  done &
done
wait
```

**Expected result:** Within seconds, HikariCP active connections reach `hikaricp_connections_max`; subsequent legitimate `getNodes()` calls return `INTERNAL` / `UNAVAILABLE` gRPC status codes; the `GrpcHighDBConnections` alert fires (threshold: >75% pool utilization for 5 min). Clients can no longer retrieve the address book to discover consensus nodes.