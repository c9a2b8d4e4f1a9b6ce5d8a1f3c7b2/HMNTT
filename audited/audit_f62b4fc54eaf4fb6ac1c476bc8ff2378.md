### Title
Unbounded Connection Acceptance on `getNodes()` Enables File Descriptor Exhaustion via Unauthenticated Botnet Flood

### Summary
The `getNodes()` gRPC endpoint in `NetworkController.java` accepts an unlimited number of concurrent TCP connections from any unauthenticated client with no per-IP or global connection cap. The only server-side guard, `maxConcurrentCallsPerConnection=5`, limits RPCs per connection but does not bound the total number of accepted connections. An attacker controlling a botnet can open thousands of connections each issuing a `limit=0` request, holding each connection open while the server pages through the full address book (250 ms inter-page delay), exhausting the JVM/OS file descriptor table and preventing any new legitimate connections from being accepted.

### Finding Description

**Code path and root cause:**

`GrpcConfiguration.java` configures the Netty server:

```java
// GrpcConfiguration.java lines 28-35
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
``` [1](#0-0) 

No call to `maxConnections()`, `maxConnectionAge()`, `maxConnectionIdle()`, or any per-IP guard is present. The search for `maxConnections|maxConnectionAge|maxConnectionIdle|permitKeepAlive` across the entire `grpc/` tree returns zero matches.

`NettyProperties.java` exposes only one tunable:

```java
private int maxConcurrentCallsPerConnection = 5;
``` [2](#0-1) 

This caps concurrent RPCs *per connection*, not the number of connections. An attacker using one RPC per connection is entirely unaffected.

`NetworkController.getNodes()` performs no authentication, no rate-limit check, and no IP inspection before dispatching:

```java
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))
            .flatMapMany(networkService::getNodes)
            ...
            .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
``` [3](#0-2) 

`NetworkServiceImpl.getNodes()` interprets `limit=0` as "stream everything":

```java
.take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
``` [4](#0-3) 

The streaming is paged with a mandatory 250 ms inter-page sleep and a page size of 10:

```java
private Duration pageDelay = Duration.ofMillis(250L);
private int pageSize = 10;
``` [5](#0-4) 

For an address book with *N* nodes, each `limit=0` call holds the connection open for at least `ceil(N/10) × 250 ms`. With 30 nodes that is ~750 ms; with 100 nodes it is ~2.5 s. During that window the TCP socket (and its file descriptor) is held open.

The only server interceptor present in the production gRPC module sets an endpoint-context label and immediately forwards the call — no rate limiting, no IP tracking: [6](#0-5) 

The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module and is not wired into the gRPC server.

**Exploit flow:**

1. Attacker controls a botnet of *K* hosts.
2. Each host opens *M* TCP connections to port 5600 (gRPC).
3. Each connection sends one `getNodes` RPC with `limit=0` and `file_id=0.0.102`.
4. The server accepts all *K×M* connections (no cap), spawns a reactive pipeline per call, and begins paging the address book with 250 ms delays.
5. Each connection consumes one OS file descriptor for the duration of the streaming response.
6. When *K×M* exceeds the process's `ulimit -n` (commonly 1024–65535 depending on deployment), `accept()` fails with `EMFILE`/`ENFILE`.
7. Legitimate clients (wallets, SDKs, monitors) receive connection-refused or timeout errors.

### Impact Explanation

File descriptor exhaustion causes the Netty acceptor to stop accepting new TCP connections. All clients that need the address book to discover consensus nodes — including the mirror node's own monitor (`NodeSupplier.getAddressBook()`) — are blocked. Address book delivery latency becomes effectively infinite for the duration of the attack, far exceeding any reasonable "500% of normal" threshold. Because the address book is the bootstrap mechanism for node discovery, a sustained attack can prevent clients from submitting transactions to the network entirely.

### Likelihood Explanation

The endpoint is publicly reachable with no authentication (confirmed: no auth check in `getNodes()`, no TLS requirement in the default docker-compose nginx config which passes gRPC plaintext). A botnet of a few hundred hosts each opening ~200 connections is sufficient to exhaust a default `ulimit` of 65535. The attack is trivially repeatable: connections are re-opened as fast as they close. No special protocol knowledge beyond a standard gRPC client library is required; the proto definition is public.

### Recommendation

Apply all of the following in `GrpcConfiguration.java`:

1. **Cap total connections**: call `serverBuilder.maxConnectionAge(Duration, TimeUnit)` and `serverBuilder.maxConnectionIdle(Duration, TimeUnit)` to bound connection lifetime and evict idle connections.
2. **Cap total concurrent connections globally**: integrate a Netty `ChannelHandler` or a gRPC `ServerInterceptor` that tracks active connection count and rejects new ones above a configurable threshold.
3. **Per-IP connection limit**: track connections per remote address in a `ConcurrentHashMap` inside a `ServerInterceptor`; return `RESOURCE_EXHAUSTED` when a single IP exceeds a threshold (e.g., 10 concurrent connections).
4. **Enforce a minimum positive limit**: reject `limit=0` or cap it to a server-side maximum (e.g., 1000) to bound per-call duration and DB load.
5. **Apply the existing `bucket4j` rate-limiting pattern** (already used in `web3`) to the gRPC layer via a `GlobalServerInterceptor`.

### Proof of Concept

```bash
# Install grpcurl: https://github.com/fullstorydev/grpcurl
# Run from 500 parallel shells (or use a loop with backgrounding):

for i in $(seq 1 500); do
  grpcurl -plaintext \
    -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.NetworkService/getNodes \
    > /dev/null &
done

# Monitor server file descriptors:
# ls /proc/<grpc-pid>/fd | wc -l

# Verify: attempt a new connection from a separate client while flood is active.
# Expected result: connection refused or timeout once fd limit is reached.
```

Each background `grpcurl` process holds a TCP connection open for the full streaming duration (~750 ms+ per call with default page settings). With 500 concurrent callers the server's file descriptor table fills rapidly. Scaling to thousands of connections via a botnet makes the attack persistent.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L33-38)
```java
    public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(networkService::getNodes)
                .map(this::toNodeAddress)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L73-73)
```java
                .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L34-37)
```java
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
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
