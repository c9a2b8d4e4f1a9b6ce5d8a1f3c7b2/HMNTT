### Title
Unauthenticated gRPC `getNodes()` Flood — No Global Rate Limit or Connection Cap Enables DoS

### Summary
The `getNodes()` handler in `NetworkController.java` accepts unlimited concurrent server-streaming RPCs from any unauthenticated caller. The only server-side guard (`maxConcurrentCallsPerConnection = 5`) is scoped per-TCP-connection, not globally, so an attacker opening many connections multiplies the allowed concurrency without bound. Each in-flight stream holds a `Schedulers.boundedElastic()` thread and a database connection for its entire lifetime, making thread-pool and DB-pool exhaustion straightforward.

### Finding Description

**Exact code path**

`getNodes()` in `NetworkController.java` (lines 33–43) subscribes a new reactive pipeline for every incoming RPC with no guard:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java  lines 33-43
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(networkService::getNodes)
            .map(this::toNodeAddress)
            .onErrorMap(ProtoUtil::toStatusRuntimeException)
            .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
    ...
}
```

`NetworkServiceImpl.getNodes()` (lines 55–77) schedules repeated DB pages on `Schedulers.boundedElastic()`:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java  lines 68-76
return Flux.defer(() -> page(context))
        .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                .jitter(0.5)
                .withFixedDelay(addressBookProperties.getPageDelay())
                .withScheduler(Schedulers.boundedElastic()))
        .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
        ...
```

When `limit = 0` the `take()` argument becomes `Long.MAX_VALUE`, keeping the stream alive until the address book is fully consumed.

**The only connection-level guard** is `maxConcurrentCallsPerConnection = 5` in `NettyProperties.java` (line 14), applied in `GrpcConfiguration.java` (line 33):

```java
// grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java  lines 28-34
ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(...) {
    return serverBuilder -> {
        serverBuilder.executor(applicationTaskExecutor);
        serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    };
}
```

This is a *per-connection* cap. There is no `maxConnectionAge`, no `maxInboundConnections`, no global concurrent-call limit, and no IP-based rate limiter anywhere in the `grpc` module. The only `ServerInterceptor` present (`GrpcInterceptor.java`, lines 16–22) only sets an `EndpointContext` tag and passes the call through unconditionally.

The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module and is never wired into the `grpc` module.

**Root cause**: The design assumes a bounded number of callers. There is no mechanism to enforce that assumption.

### Impact Explanation

Each concurrent `getNodes()` stream:
- Occupies one `boundedElastic` worker thread during every `pageDelay` sleep (default 250 ms). Reactor's `boundedElastic` scheduler caps at `10 × CPU cores` threads by default. With enough connections the scheduler queue fills and all reactive pipelines stall, including topic-message subscriptions used by consensus nodes.
- Executes one DB transaction per page via `transactionOperations.execute()`. The HikariCP pool for the gRPC service is small (documented default: shared with the service). Pool exhaustion causes every subsequent DB call — including those serving legitimate consensus-node address-book lookups — to block or fail.
- Holds an open gRPC HTTP/2 stream, consuming file descriptors and Netty channel memory.

The combined effect is that the mirror node becomes unable to serve address-book data to legitimate consensus nodes, constituting a network partition outside design parameters.

### Likelihood Explanation

No authentication or API key is required. The gRPC port (5600) is publicly exposed per the Helm chart gateway rules (`charts/hedera-mirror-grpc/values.yaml`, lines 88–91). An attacker needs only a standard gRPC client (e.g., `grpcurl`, the Hedera Java SDK, or a custom script). Opening 200 TCP connections × 5 calls each = 1 000 concurrent streams, well within a single commodity machine's capability. The attack is trivially repeatable and requires no special knowledge of the network.

### Recommendation

1. **Add a global concurrent-call limit** via `serverBuilder.maxConcurrentCallsPerConnection` combined with a hard cap on accepted connections (`NettyServerBuilder.maxConnectionAge` / `maxConnectionIdle`), or use a Netty `ChannelHandler` that tracks total active streams.
2. **Add a per-IP rate limiter** as a `ServerInterceptor` (e.g., using Bucket4j or Guava `RateLimiter`) that rejects `getNodes()` calls exceeding a threshold per source address.
3. **Bound the `getNodes()` stream duration** by enforcing a non-zero maximum `limit` in `AddressBookFilter` validation, preventing `Long.MAX_VALUE` take.
4. **Apply the existing `ThrottleManager` pattern** from the `web3` module to the `grpc` module's `NetworkController`.

### Proof of Concept

```bash
# Install grpcurl: https://github.com/fullstorydev/grpcurl
# Replace <mirror-node-host> with the target host

for i in $(seq 1 200); do
  grpcurl -plaintext \
    -d '{"file_id": {"fileNum": 102}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.NetworkService/getNodes &
done
wait
```

Each background process opens a new TCP connection and issues a `getNodes()` stream. With 200 connections × 5 concurrent calls per connection (the per-connection cap), 1 000 simultaneous reactive pipelines are created. Monitor the mirror node's `boundedElastic` thread pool saturation and HikariCP active-connection count; both will reach their ceilings within seconds, causing subsequent legitimate `getNodes()` calls to time out or return `UNAVAILABLE`.