### Title
Blocking JDBC Call in Reactive Context Enables Thread Pool Exhaustion DoS During Network Partition

### Summary
In `TopicMessageServiceImpl.subscribeTopic()`, the call to `entityRepository.findById()` inside `topicExists()` is executed **eagerly and synchronously** on the gRPC executor thread before any reactive pipeline is assembled. Because `EntityRepository` is a Spring Data JPA `CrudRepository` backed by blocking JDBC, and because there is no connection-count limit on the gRPC server, an unprivileged attacker can open many connections and flood `subscribeTopic()` with unique topic IDs during a network partition, blocking all threads in the `applicationTaskExecutor` pool and rendering the service unresponsive.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.java`, `topicExists()`, line 96:
```java
return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
```
`entityRepository.findById()` is passed as an **eager argument** to `Mono.justOrEmpty()`. Java evaluates method arguments before the call, so the blocking JDBC query executes synchronously on whatever thread invokes `topicExists()` — which is the gRPC executor thread, because `subscribeTopic()` calls `topicExists(filter)` directly at line 87 (not inside a `Mono.defer()` or `Schedulers.boundedElastic()` wrapper).

**Root cause:** The failed assumption is that wrapping a blocking call's result in `Mono.justOrEmpty()` makes it non-blocking. It does not. The JDBC call completes (or hangs) before the `Mono` is even constructed.

**Thread model:** `GrpcConfiguration.java` line 32 sets `serverBuilder.executor(applicationTaskExecutor)`, meaning every incoming gRPC call dispatches to Spring Boot's `ThreadPoolTaskExecutor`. This pool has a finite number of platform threads (default Spring Boot configuration, no virtual-thread override found in this module).

**Cache bypass:** `EntityRepository.findById()` is annotated `@Cacheable` with `expireAfterWrite=24h, maximumSize=50000`. The `unless="#result==null"` condition caches `Optional.empty()` (non-null), so non-existent IDs are cached after the first hit. However, the attacker uses a rotating set of unique, never-before-seen topic IDs (e.g., sequential integers beyond any real topic), ensuring every request is a cache miss and hits the DB.

**Network partition behavior:** `statementTimeout=10000ms` is a PostgreSQL-level directive. When the DB host is unreachable (full partition), the JDBC driver's TCP socket hangs until the OS TCP keepalive/retransmit timeout fires — typically 2–15 minutes — far exceeding the statement timeout, which requires a live DB connection to enforce.

**Exploit flow:**
1. Attacker opens K gRPC connections (no server-side connection limit is configured).
2. Each connection sends 5 concurrent `subscribeTopic()` calls (`maxConcurrentCallsPerConnection=5`), each with a distinct, uncached topic ID.
3. Each call blocks its `applicationTaskExecutor` thread in `entityRepository.findById()` waiting for a TCP timeout.
4. With K connections × 5 calls = K×5 threads blocked simultaneously.
5. Once the thread pool is saturated, all subsequent gRPC requests (including health checks routed through the same executor) queue indefinitely → service appears hung.

**Existing checks reviewed and shown insufficient:**
- `maxConcurrentCallsPerConnection=5`: Limits per-connection parallelism only; attacker opens many connections.
- `@Cacheable`: Bypassed by rotating unique topic IDs.
- `statementTimeout=10000ms`: Ineffective during full TCP-level partition.
- No total-connection limit, no per-IP rate limit, no circuit breaker on `entityRepository` calls.

### Impact Explanation
Complete DoS of the gRPC mirror node service. All `subscribeTopic` streams stall, and because the same `applicationTaskExecutor` services all gRPC calls, unrelated operations (address book queries, health probes) also starve. Downstream clients (wallets, dApps, consensus monitors) lose real-time topic message delivery. Severity: **High** (availability impact, no authentication required, no data exfiltration but full service disruption).

### Likelihood Explanation
The attacker requires only: (1) network access to port 5600, (2) a gRPC client library (freely available), and (3) the ability to open many TCP connections — standard for any internet-connected host. The network partition is a precondition the attacker does not need to cause; they simply monitor for degraded DB connectivity (observable via increased response latency) and launch the flood at that moment. The attack is repeatable and requires no credentials or special knowledge of the topic namespace beyond knowing that sequential IDs will be cache misses.

### Recommendation

1. **Wrap the blocking call in a non-blocking scheduler** (immediate fix):
   ```java
   private Mono<?> topicExists(TopicMessageFilter filter) {
       var topicId = filter.getTopicId();
       return Mono.fromCallable(() -> entityRepository.findById(topicId.getId()))
               .subscribeOn(Schedulers.boundedElastic())
               .flatMap(opt -> Mono.justOrEmpty(opt))
               ...
   }
   ```
   This offloads the JDBC call to `boundedElastic()`, which is designed for blocking I/O and has a configurable ceiling.

2. **Set a JDBC socket/connect timeout** independent of PostgreSQL's `statementTimeout`, e.g., `socketTimeout=15` in the JDBC URL, so TCP hangs are bounded.

3. **Add a server-side connection limit** via `NettyServerBuilder.maxConnectionAge()` or a Traefik/Envoy rate-limit middleware to cap total concurrent connections per source IP.

4. **Enable virtual threads** (`spring.threads.virtual.enabled=true`) as a partial mitigation — virtual threads are cheap enough that exhaustion requires far more connections, though carrier-thread pinning on JDBC synchronized blocks can still occur.

### Proof of Concept

```python
import grpc
import concurrent.futures
from proto import consensus_service_pb2_grpc, consensus_service_pb2, timestamp_pb2, mirror_basic_pb2

TARGET = "mirror-node-grpc:5600"
NUM_CONNECTIONS = 50   # 50 connections × 5 calls = 250 blocked threads
CALLS_PER_CONN = 5

def flood_connection(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    futures = []
    for i in range(CALLS_PER_CONN):
        # Use unique topic IDs to bypass the entity cache
        topic_id = conn_id * 1000 + i + 9_000_000  # IDs unlikely to exist
        query = consensus_service_pb2.ConsensusTopicQuery(
            topicID=mirror_basic_pb2.TopicID(topicNum=topic_id),
            consensusStartTime=timestamp_pb2.Timestamp(seconds=0)
        )
        # Non-blocking iterator open; server blocks on findById()
        futures.append(stub.subscribeTopic(query))
    # Hold connections open while threads are blocked server-side
    import time; time.sleep(300)

# Step 1: Induce or wait for network partition between grpc pod and DB
# Step 2: Launch flood
with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CONNECTIONS) as ex:
    list(ex.map(flood_connection, range(NUM_CONNECTIONS)))

# Expected result: applicationTaskExecutor saturated; all subsequent gRPC
# calls (including legitimate subscribers) receive UNAVAILABLE or hang.
```