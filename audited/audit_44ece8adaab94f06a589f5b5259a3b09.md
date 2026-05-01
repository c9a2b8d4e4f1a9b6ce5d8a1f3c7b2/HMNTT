### Title
Unauthenticated gRPC `getNodes()` Endpoint Enables Unbounded Resource Exhaustion

### Summary
`NetworkController.getNodes()` is exposed as a public gRPC service via `@GrpcService` with zero authentication or rate-limiting in the production code path. Any unauthenticated caller from any network location can invoke it with `limit=0`, which internally maps to `Long.MAX_VALUE` items, triggering unbounded paginated database queries that exhaust the DB connection pool and thread executor, denying service to legitimate clients.

### Finding Description

**Exact code path:**

`NetworkController` is registered as a gRPC service with no interceptor: [1](#0-0) 

The only `ServerInterceptor` in the entire grpc module lives exclusively in the **test** source tree and only sets an endpoint-context label — it performs no authentication: [2](#0-1) 

`GrpcConfiguration` (the sole production server customizer) only sets `maxConcurrentCallsPerConnection` and an executor — no auth, no TLS enforcement: [3](#0-2) 

**Root cause — unbounded query when `limit=0`:**

`AddressBookFilter.limit` has a `@Min(0)` constraint, so 0 is valid: [4](#0-3) 

`NetworkServiceImpl.getNodes()` treats `limit == 0` as "return everything" by substituting `Long.MAX_VALUE`: [5](#0-4) 

Each page triggers a synchronous DB transaction, and pages repeat with a 250 ms delay until the address book is exhausted: [6](#0-5) 

**Why the only existing guard is insufficient:**

`maxConcurrentCallsPerConnection` defaults to 5 and is enforced **per connection**, not globally: [7](#0-6) 

There is no per-IP connection limit, no global call rate limiter, and no TLS/mTLS requirement. The web3 throttle manager (`ThrottleManagerImpl`) is entirely separate and does not apply to the gRPC service.

The official documentation explicitly demonstrates plaintext, credential-free invocation: [8](#0-7) 

### Impact Explanation
An attacker opening `N` TCP connections can sustain up to `5N` concurrent `getNodes(limit=0)` streams simultaneously. Each stream holds a DB connection and a bounded-elastic scheduler thread for the duration of the full address book scan. Saturating the DB connection pool causes all other gRPC and internal operations that require DB access to queue or fail, resulting in a complete denial of service for the mirror node's gRPC API. Because `getNodes` is the mechanism by which Hedera SDK clients discover network topology, disruption here prevents clients from learning node addresses, effectively blocking new transaction submission to the network.

### Likelihood Explanation
Preconditions are minimal: network reachability to port 5600 (default) and a standard gRPC client (e.g., `grpcurl`, Hedera SDK, or any protobuf-capable HTTP/2 client). No credentials, tokens, or prior knowledge beyond the publicly documented proto definition are required. The attack is trivially scriptable, repeatable, and can be sustained indefinitely from a single host with multiple connections.

### Recommendation
1. **Add a global server-side rate-limiting interceptor** (`@GlobalServerInterceptor` in production, not test scope) that enforces per-IP and global call-rate limits using a token-bucket or similar mechanism, analogous to `ThrottleManagerImpl` in the web3 module.
2. **Enforce a hard maximum on `limit`** in `NetworkController.toFilter()` or `AddressBookFilter` validation — reject or cap requests where `limit == 0` or `limit` exceeds a configured maximum (e.g., 1000).
3. **Require mTLS or a bearer-token interceptor** for production deployments, or document and enforce network-layer access controls (firewall/ingress rules) that restrict port 5600 to trusted clients only.
4. **Set `maxConnectionsPerIp`** at the Netty layer via `ServerBuilderCustomizer` to bound the number of connections a single source IP can open.

### Proof of Concept
```bash
# Step 1: Install grpcurl (no credentials needed)
# Step 2: Flood with concurrent unlimited-result streams from multiple connections

for i in $(seq 1 50); do
  grpcurl -plaintext \
    -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.NetworkService/getNodes \
    > /dev/null &
done
wait

# Each background process holds a DB connection + thread for the full scan duration.
# 50 connections × 5 concurrent calls/connection = 250 simultaneous DB-backed streams.
# DB connection pool exhaustion causes all subsequent gRPC calls to stall or error.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L25-43)
```java
@GrpcService
@CustomLog
@RequiredArgsConstructor
final class NetworkController extends NetworkServiceGrpc.NetworkServiceImplBase {

    private final NetworkService networkService;

    @Override
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

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L12-22)
```java
@GlobalServerInterceptor
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/AddressBookFilter.java (L17-18)
```java
    @Min(0)
    private final int limit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L68-76)
```java
        return Flux.defer(() -> page(context))
                .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                        .jitter(0.5)
                        .withFixedDelay(addressBookProperties.getPageDelay())
                        .withScheduler(Schedulers.boundedElastic()))
                .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Querying for address book: {}", filter))
                .doOnComplete(() -> log.info("Retrieved {} nodes from the address book", context.getCount()));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L79-107)
```java
    private Flux<AddressBookEntry> page(AddressBookContext context) {
        return transactionOperations.execute(t -> {
            var addressBookTimestamp = context.getAddressBookTimestamp();
            var nodeStakeMap = context.getNodeStakeMap();
            var nextNodeId = context.getNextNodeId();
            var pageSize = addressBookProperties.getPageSize();
            var nodes = addressBookEntryRepository.findByConsensusTimestampAndNodeId(
                    addressBookTimestamp, nextNodeId, pageSize);
            var endpoints = new AtomicInteger(0);

            nodes.forEach(node -> {
                // Override node stake
                node.setStake(nodeStakeMap.getOrDefault(node.getNodeId(), 0L));
                // This hack ensures that the nested serviceEndpoints is loaded eagerly and voids lazy init exceptions
                endpoints.addAndGet(node.getServiceEndpoints().size());
            });

            if (nodes.size() < pageSize) {
                context.completed();
            }

            log.info(
                    "Retrieved {} address book entries and {} endpoints for timestamp {} and node ID {}",
                    nodes.size(),
                    endpoints,
                    addressBookTimestamp,
                    nextNodeId);
            return Flux.fromIterable(nodes);
        });
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** docs/grpc/README.md (L35-37)
```markdown
Example invocation using `grpcurl`:

`grpcurl -plaintext -d '{"file_id": {"fileNum": 102}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.NetworkService/getNodes`
```
