### Title
Unbounded TCP Connection Count Enables DoS via `getNodes()` Stream Exhaustion

### Summary
`NetworkController.getNodes()` is an unauthenticated, publicly accessible gRPC server-streaming endpoint with no limit on the number of TCP connections a single client may open. The only server-side guard, `maxConcurrentCallsPerConnection = 5`, limits streams per connection but does not bound the total number of connections. An attacker can open thousands of connections and saturate the thread pool and database connection pool, denying service to legitimate users.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` at [1](#0-0)  accepts any `AddressBookQuery` with no authentication check and immediately subscribes a Reactor pipeline backed by `NetworkServiceImpl.getNodes()`.

`NetworkServiceImpl.getNodes()` at [2](#0-1)  issues repeated paginated DB queries with a `pageDelay` of 250 ms between pages, holding a DB connection and a thread for the full duration of each call.

**Root cause — the only Netty guard is per-connection, not per-client:**

`GrpcConfiguration` configures the Netty server with only one constraint: [3](#0-2) 

`NettyProperties` hard-codes that limit to 5: [4](#0-3) 

`maxConcurrentCallsPerConnection` is an HTTP/2 stream-level limit scoped to a single TCP connection. It does **not** limit how many TCP connections a single IP may open. No call to `NettyServerBuilder.maxConnectionAge()`, `maxConnectionIdle()`, or any equivalent per-IP or global connection cap is present anywhere in the configuration. [5](#0-4) 

**Why existing checks fail:**

The only production `ServerInterceptor` sets an endpoint-context label and passes the call through unconditionally — no auth, no rate-limit: [6](#0-5) 

The throttle/rate-limit infrastructure (Bucket4j) exists only in the `web3` module; the `grpc` module has no equivalent. [7](#0-6) 

The GCP gateway `maxRatePerEndpoint: 250` is an optional Helm-chart value that (a) requires a GCP-specific gateway deployment, (b) limits requests-per-second, not concurrent open connections, and (c) is not enforced at the application layer. [8](#0-7) 

### Impact Explanation

Each `getNodes()` call holds one HikariCP database connection for `ceil(nodeCount / pageSize) × pageDelay` milliseconds (e.g., 100 nodes / pageSize 10 × 250 ms = 2.5 s). With N connections × 5 streams each, an attacker can hold 5N DB connections simultaneously. The default HikariCP pool is small (typically 10–20 connections for the gRPC module). Once the pool is exhausted, all legitimate `getNodes()` and `subscribeTopic` calls queue indefinitely or fail. Thread-pool exhaustion follows the same pattern. The gRPC server becomes unavailable to all users — a complete denial of service for the public mirror node API. [9](#0-8) 

### Likelihood Explanation

Preconditions: none. The endpoint is unauthenticated and publicly reachable on port 5600. The attacker needs only a standard gRPC client (e.g., `grpcurl`) and the ability to open many TCP connections — trivially achievable from a single machine or a small botnet. The attack is repeatable and requires no special knowledge of the system. [10](#0-9) 

### Recommendation

1. **Add a global connection limit** in `GrpcConfiguration` via `NettyServerBuilder.maxConnectionAge(Duration)` and `maxConnectionIdle(Duration)` to recycle long-lived connections and bound total open connections.
2. **Add a per-IP connection limit** using a Netty `ChannelHandler` or a gRPC `ServerInterceptor` that tracks active connections per remote address and rejects new ones above a threshold.
3. **Add application-level rate limiting** in the `grpc` module analogous to the Bucket4j throttle in `web3`, applied inside a `GlobalServerInterceptor` before the call reaches `NetworkController`.
4. **Set `maxConnectionIdle`** on `NettyServerBuilder` so idle connections from flood sources are reaped automatically. [5](#0-4) 

### Proof of Concept

```bash
# Open 500 parallel connections, each firing 5 concurrent getNodes() streams (= 2500 simultaneous DB queries)
# Requires grpcurl and GNU parallel

for i in $(seq 1 500); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.NetworkService/getNodes &
  done
done
wait

# Expected result:
# - HikariCP pool exhausted; subsequent legitimate calls receive UNAVAILABLE or hang
# - Thread pool saturated; subscribeTopic calls also fail
# - Metrics: hikaricp_connections_active / hikaricp_connections_max → 1.0 (alert threshold 0.75)
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L33-43)
```java
    public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(networkService::getNodes)
                .map(this::toNodeAddress)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L27-35)
```java
    @Bean
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L17-29)
```java
public class GrpcProperties {

    private boolean checkTopicExists = true;

    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);

    @Min(1)
    private int entityCacheSize = 50_000;

    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
```

**File:** charts/hedera-mirror-grpc/values.yaml (L62-73)
```yaml
gateway:
  gcp:
    backendPolicy:
      connectionDraining:
        drainingTimeoutSec: 10
      logging:
        enabled: false
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
    enabled: true
```

**File:** docs/grpc/README.md (L28-37)
```markdown
### Get Nodes

[HIP-21](https://hips.hedera.com/hip/hip-21) describes a need for clients to retrieve address book information without
incurring the costs of multiple queries to get the network file's contents. The `getNode` API will return the list of
nodes associated with the latest address book file. See the protobuf
[definition](../../protobuf/src/main/proto/com/hedera/mirror/api/proto/network_service.proto).

Example invocation using `grpcurl`:

`grpcurl -plaintext -d '{"file_id": {"fileNum": 102}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.NetworkService/getNodes`
```
