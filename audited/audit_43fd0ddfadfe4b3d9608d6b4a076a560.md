### Title
Unbounded gRPC Inbound Metadata Size Enables Memory Exhaustion via Header Flooding

### Summary
The `grpcServerConfigurer()` bean in `GrpcConfiguration.java` configures the `NettyServerBuilder` with only a per-connection call concurrency limit, but never calls `maxInboundMetadataSize()`. The gRPC-Java default for this value is `Integer.MAX_VALUE` (~2 GB), meaning the server advertises no practical header size limit to clients via HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE`. Any unauthenticated external user can send gRPC requests carrying arbitrarily large metadata, forcing the server to buffer it in heap memory before any application logic runs, enabling memory exhaustion that degrades the transaction read pipeline.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 27–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    // maxInboundMetadataSize() is never called
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java` (lines 11–15) defines only `maxConcurrentCallsPerConnection = 5`; there is no `maxInboundMetadataSize` field anywhere in the `grpc/` module (confirmed by exhaustive grep).

**Root cause:** `io.grpc.internal.AbstractServerImplBuilder` initializes `maxInboundMetadataSize = Integer.MAX_VALUE`. When `NettyServerBuilder` is not explicitly configured with a lower value, it propagates `Integer.MAX_VALUE` as the HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE` advertised to connecting clients. Clients are therefore never told to limit header sizes.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (no authentication required).
2. On each connection, attacker sends up to 5 concurrent gRPC calls (the per-connection limit), each carrying custom metadata headers sized at, e.g., 4–16 MB (within HTTP/2 frame limits).
3. The Netty HTTP/2 codec and gRPC layer allocate heap memory to hold the full `Metadata` object before any handler or interceptor runs.
4. The `GrpcInterceptor` (`grpc/src/test/java/…/interceptor/GrpcInterceptor.java`, line 21) passes the unsanitized `headers` object directly to `next.startCall(call, headers)` with no size check.
5. With N connections × 5 calls × multi-MB metadata, heap pressure grows rapidly.

**Why existing checks fail:** `maxConcurrentCallsPerConnection = 5` limits calls per connection but imposes no limit on the number of connections, no `maxConnectionAge`, no `maxConnectionIdle`, and no rate limiting. The per-call concurrency guard is orthogonal to per-call metadata size.

### Impact Explanation
Heap memory is consumed proportionally to (number of connections × 5 × metadata size per call). At 1,000 connections × 5 calls × 4 MB metadata = ~20 GB of metadata buffering, far exceeding typical JVM heap. This causes:
- **OutOfMemoryError** crashing the gRPC service entirely, making topic subscription and address book queries unavailable.
- **GC pressure / stop-the-world pauses** degrading the transaction read pipeline (DB polling via `RetrieverProperties`, Redis listener) even before OOM, causing subscription timeouts and missed messages for legitimate clients.
- The gRPC port (5600) is publicly documented and requires no credentials, making this a zero-barrier attack.

### Likelihood Explanation
The gRPC API is publicly exposed with no authentication. An attacker needs only a standard gRPC client (e.g., `grpcurl`, any gRPC library) and the ability to set custom metadata headers. No special privileges, credentials, or knowledge of internal state are required. The attack is trivially scriptable, repeatable, and can be sustained indefinitely since there is no connection-level rate limiting or idle timeout configured. This is a realistic denial-of-service vector for any internet-facing deployment.

### Recommendation
In `grpcServerConfigurer()`, add an explicit `maxInboundMetadataSize` call with a safe upper bound (e.g., 8 KB, matching the gRPC-Java recommended default):

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    serverBuilder.maxInboundMetadataSize(nettyProperties.getMaxInboundMetadataSize()); // e.g., 8192
};
```

Add `maxInboundMetadataSize` to `NettyProperties` with a default of `8192` and a `@Min(1)` constraint. Additionally, consider adding `maxConnectionAge`, `maxConnectionIdle`, and `maxConnectionAgeGrace` to bound long-lived connections.

### Proof of Concept
```python
import grpc
from grpc import metadata_call_credentials

# Build ~4 MB of metadata
large_value = "A" * (4 * 1024 * 1024)
metadata = [("x-attack-header", large_value)]

channel = grpc.insecure_channel("mirror-node-host:5600")

# Open many concurrent calls with oversized metadata
# Each call forces the server to buffer 4 MB before any handler runs
import threading

def flood():
    stub = ...  # any generated stub, e.g. ConsensusServiceStub
    try:
        for resp in stub.subscribeTopic(request, metadata=metadata):
            pass
    except:
        pass

threads = [threading.Thread(target=flood) for _ in range(200)]
for t in threads:
    t.start()
# 200 connections × 5 concurrent calls × 4 MB = ~4 GB heap pressure
``` [1](#0-0) [2](#0-1)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```
