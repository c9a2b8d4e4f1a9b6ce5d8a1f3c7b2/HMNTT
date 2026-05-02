### Title
Unauthenticated Multi-Connection Flood of `getNodes()` Bypasses Per-Connection Concurrency Limit, Enabling DoS via DB Exhaustion

### Summary
The `getNodes()` endpoint in `NetworkController` is publicly accessible with no authentication and no global or per-IP rate limiting. The only concurrency control is `maxConcurrentCallsPerConnection = 5`, which is a per-connection limit enforced by Netty. An unprivileged attacker can trivially bypass this by opening many parallel TCP/HTTP2 connections, each carrying 5 concurrent `getNodes()` streams, multiplying the number of concurrent database queries without bound.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (lines 33–43) accepts any `AddressBookQuery` with no authentication check and immediately fans out to `networkService::getNodes`:

```java
// NetworkController.java:33-38
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(networkService::getNodes)
            .map(this::toNodeAddress)
            .onErrorMap(ProtoUtil::toStatusRuntimeException)
            .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
``` [1](#0-0) 

`NetworkServiceImpl.getNodes()` (lines 55–77) issues at minimum 3 DB queries on every call (address book timestamp, node stake timestamp, node stake map), then pages through `addressBookEntryRepository` in a loop with a 250 ms delay between pages until all entries are returned: [2](#0-1) 

When `limit = 0` (the proto default), the `.take()` uses `Long.MAX_VALUE`, meaning the stream stays open and pages indefinitely: [3](#0-2) 

**The only concurrency control** is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`, applied via `serverBuilder.maxConcurrentCallsPerConnection(...)` in `GrpcConfiguration`: [4](#0-3) [5](#0-4) 

**Root cause / failed assumption:** The design assumes that limiting streams per connection is sufficient. It is not. HTTP/2 multiplexing is a per-connection concept; nothing prevents an attacker from opening an arbitrary number of connections. There is no per-IP connection limit, no global concurrent-call cap, and no request-rate limiter anywhere in the gRPC module. The `GrpcInterceptor` only sets an endpoint context string for table-usage tracking — it performs no throttling or auth: [6](#0-5) 

By contrast, the web3 REST module has a full bucket4j rate-limiting stack (`ThrottleManagerImpl`, `ThrottleConfiguration`). No equivalent exists for gRPC.

### Impact Explanation

Each `getNodes()` call holds a DB connection for the duration of the paging loop (multiple queries, 250 ms apart). With N attacker connections × 5 streams each, the server sustains N×5 concurrent long-lived DB transactions. The DB connection pool (default `statementTimeout = 10 000 ms`) will be exhausted, causing all gRPC and potentially shared DB operations to queue or fail. This is a complete denial-of-service against the gRPC service achievable from a single host with no credentials. Severity: **High**.

### Likelihood Explanation

Preconditions: none — the endpoint is unauthenticated and publicly exposed on port 5600. The attack requires only a standard gRPC client (e.g., `grpcurl`, the Hedera Java SDK, or a custom script). Opening 20–50 connections with 5 streams each is trivial and repeatable. No exploit code or special knowledge is required beyond the published proto definition.

### Recommendation

1. **Add a global concurrent-call limit** via a `ServerInterceptor` that tracks in-flight `getNodes()` calls with an `AtomicInteger` and rejects with `RESOURCE_EXHAUSTED` when a threshold is exceeded.
2. **Add a per-IP rate limiter** (e.g., bucket4j keyed by remote address) in a `GlobalServerInterceptor`, mirroring the pattern already used in the web3 module (`ThrottleManagerImpl`).
3. **Set `maxInboundConnections`** on `NettyServerBuilder` to cap total simultaneous TCP connections.
4. **Enforce a minimum non-zero `limit`** in `AddressBookFilter` so streams cannot run indefinitely.
5. Consider deploying an L7 proxy (Envoy, nginx) in front of the gRPC port with per-IP connection and RPS limits as a defense-in-depth layer.

### Proof of Concept

```bash
# Install grpcurl: https://github.com/fullstorydev/grpcurl
# Open 20 connections, each with 5 concurrent getNodes streams (100 total concurrent DB queries)

for conn in $(seq 1 20); do
  for stream in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"file_id": {"fileNum": 102}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.NetworkService/getNodes &
  done
done
wait
```

Each background process holds an open gRPC stream that pages through the address book, consuming a DB connection for the duration. With 100 concurrent streams, the DB connection pool is exhausted and legitimate requests begin receiving errors. The attack is repeatable immediately after streams complete, with no cooldown enforced by the server.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L33-38)
```java
    public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(networkService::getNodes)
                .map(this::toNodeAddress)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L55-77)
```java
    public Flux<AddressBookEntry> getNodes(AddressBookFilter filter) {
        var fileId = filter.getFileId();
        if (!getValidFileIds().contains(fileId)) {
            throw new IllegalArgumentException(INVALID_FILE_ID);
        }

        long addressBookTimestamp = addressBookRepository
                .findLatestTimestamp(fileId.getId())
                .orElseThrow(() -> new EntityNotFoundException(fileId));
        long nodeStakeTimestamp = nodeStakeRepository.findLatestTimestamp().orElse(NODE_STAKE_EMPTY_TABLE_TIMESTAMP);
        var nodeStakeMap = nodeStakeRepository.findAllStakeByConsensusTimestamp(nodeStakeTimestamp);
        var context = new AddressBookContext(addressBookTimestamp, nodeStakeMap);

        return Flux.defer(() -> page(context))
                .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                        .jitter(0.5)
                        .withFixedDelay(addressBookProperties.getPageDelay())
                        .withScheduler(Schedulers.boundedElastic()))
                .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Querying for address book: {}", filter))
                .doOnComplete(() -> log.info("Retrieved {} nodes from the address book", context.getCount()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L16-22)
```java
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```
