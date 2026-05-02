### Title
Unauthenticated gRPC `getNodes()` Endpoint Lacks Global Rate Limiting and Connection Throttling, Enabling Resource Exhaustion DoS

### Summary
The `getNodes()` handler in `NetworkController` accepts requests from any unauthenticated caller with no global rate limit or per-IP connection cap. The only server-side guard — `maxConcurrentCallsPerConnection=5` — is scoped per HTTP/2 connection, not globally, so an attacker opening many connections can drive arbitrarily many concurrent reactive pipelines. Each pipeline issues repeated transactional database reads via a shared `boundedElastic()` scheduler, enabling database connection pool exhaustion and scheduler saturation that degrades or blocks legitimate queries.

### Finding Description

**Entry point** — `NetworkController.getNodes()` ( [1](#0-0) ) accepts any `AddressBookQuery` with no authentication check, no rate-limit guard, and no per-caller concurrency cap. It immediately subscribes a reactive pipeline backed by `networkService::getNodes`.

**Reactive pipeline** — `NetworkServiceImpl.getNodes()` ( [2](#0-1) ) builds:
```java
Flux.defer(() -> page(context))
    .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
        .withFixedDelay(addressBookProperties.getPageDelay())   // 250 ms default
        .withScheduler(Schedulers.boundedElastic()))
    .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
```
With `limit=0` the `.take()` uses `Long.MAX_VALUE`. The stream terminates only when `context.isComplete()` becomes true (set when a page returns fewer rows than `pageSize`). Each page call wraps a read-only DB transaction ( [3](#0-2) ), consuming a connection from the pool and a thread from the shared `boundedElastic()` scheduler.

**The only concurrency guard** — `maxConcurrentCallsPerConnection=5` ( [4](#0-3) ) is applied per HTTP/2 connection ( [5](#0-4) ). There is no global concurrent-call cap, no per-IP connection limit, and no rate limiter on the gRPC service (the only throttle in the codebase is scoped to the `web3` module, not `grpc`).

**Failed assumption**: the design assumes that 5 concurrent streams per connection is a sufficient bound. It is not, because nothing limits the number of connections an attacker may open.

### Impact Explanation
Each concurrent `getNodes` stream holds a DB connection for every 250 ms page interval and occupies a `boundedElastic()` worker thread during each page fetch. With N attacker connections, up to 5N concurrent streams run simultaneously. At N=200 connections (easily achievable from a single host), 1,000 concurrent streams each issuing DB reads every 250 ms saturate a typical connection pool (default HikariCP pool size is 10) and fill the `boundedElastic()` task queue, causing legitimate gRPC calls — including address-book queries from consensus nodes — to queue indefinitely or time out. The mirror node's ability to serve gossip-related queries is effectively denied.

### Likelihood Explanation
No privileges, credentials, or special network position are required. A single attacker machine can open hundreds of TCP connections to port 5600 and issue 5 concurrent `getNodes` streams per connection using any standard gRPC client (e.g., `grpcurl`, a scripted Java/Go client). The attack is trivially repeatable and scriptable. The public documentation even provides the exact `grpcurl` invocation with `limit=0`. [6](#0-5) 

### Recommendation
1. **Global concurrent-call cap**: configure `NettyServerBuilder.maxConcurrentCallsPerConnection` alongside a global `maxConnectionAge` and `maxConnectionIdle` to bound total server-side state.
2. **Per-IP connection limit**: enforce at the ingress/proxy layer (nginx `limit_conn`, GCP backend policy) or via a gRPC `ServerInterceptor` that tracks active calls per remote address.
3. **Rate limiting on the gRPC service**: add a `ServerInterceptor` using the same bucket4j pattern already used in the `web3` module to cap `getNodes` invocations per second globally and per source IP.
4. **Stream timeout**: add `.timeout(maxDuration)` to the `getNodes` Flux so a single stream cannot hold resources indefinitely if the address book is unusually large or paging stalls.

### Proof of Concept
```bash
# Open 200 parallel connections, each with 5 concurrent getNodes streams (1000 total)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.NetworkService/getNodes &
  done
done
wait
```
**Expected result**: DB connection pool exhausted; subsequent legitimate `getNodes` or `subscribeTopic` calls return `RESOURCE_EXHAUSTED` or hang until the attacker connections are closed.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-34)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** docs/grpc/README.md (L35-37)
```markdown
Example invocation using `grpcurl`:

`grpcurl -plaintext -d '{"file_id": {"fileNum": 102}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.NetworkService/getNodes`
```
