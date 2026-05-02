### Title
Unbounded gRPC Connections Allow Unprivileged Gauge Inflation and Metric-Masking DoS

### Summary
`TopicMessageServiceImpl.subscribeTopic()` unconditionally increments `subscriberCount` on every subscription with no cap on total active subscriptions or total connections. The only server-side guard is `maxConcurrentCallsPerConnection = 5`, which limits calls per TCP connection but places no bound on the number of connections an attacker may open. An unprivileged attacker can open arbitrarily many connections—each carrying up to 5 long-lived subscriptions—causing the `hiero.mirror.grpc.subscribers` Gauge to reflect an arbitrarily large count while simultaneously exhausting server-side resources.

### Finding Description

**Gauge registration** — `init()` wires `subscriberCount` directly into a Micrometer Gauge with no ceiling: [1](#0-0) 

**Counter lifecycle** — every successful subscription increments the counter; `doFinally` decrements it only on terminal signals (complete / error / cancel): [2](#0-1) 

**The only existing guard** — `maxConcurrentCallsPerConnection` is set to 5 per connection: [3](#0-2) [4](#0-3) 

This guard is **per-connection only**. There is no `maxConnections`, no per-IP limit, and no authentication on the gRPC endpoint. An attacker opening *N* TCP connections can hold *5N* concurrent subscriptions open indefinitely. Each open subscription keeps `subscriberCount` incremented, so the Gauge reads *5N* — a value entirely under attacker control.

`ConsensusController` does register a cancel handler (`disposable::dispose`) so the count is eventually decremented when a connection is torn down, but the attacker simply keeps the connections alive. [5](#0-4) 

There is no check anywhere in `subscribeTopic()` that reads `subscriberCount` and rejects new subscriptions above a threshold.

### Impact Explanation

1. **Metric poisoning / operator confusion** — operators monitoring `hiero.mirror.grpc.subscribers` see a number that appears to represent legitimate load. Alerts tuned to "high subscriber count = normal traffic spike" will not fire, masking the attack.
2. **Resource exhaustion** — each live subscription holds a Reactor pipeline, a `TopicContext`, a DB polling thread (via `PollingTopicMessageRetriever`/`SharedPollingTopicListener`), and a Netty channel slot. With no connection ceiling, the attacker can exhaust thread pools, DB connection pools, and heap, causing a full service outage.
3. **Severity** — classified as High non-network DoS: no authentication, no rate limit, fully reproducible from a single host with a scripted gRPC client.

### Likelihood Explanation

Any client that can reach the gRPC port (default 5600) can exploit this. No credentials, no special protocol knowledge beyond the public protobuf schema, and no elevated privileges are required. Standard gRPC client libraries (grpc-java, grpcurl, etc.) make it trivial to script thousands of parallel `subscribeTopic` calls. The attack is repeatable and can be sustained indefinitely as long as the attacker keeps TCP connections open.

### Recommendation

1. **Enforce a global subscription ceiling** — read `subscriberCount` at the start of `subscribeTopic()` and return an `RESOURCE_EXHAUSTED` gRPC status if it exceeds a configurable maximum (e.g., `grpcProperties.getMaxSubscribers()`).
2. **Add a per-IP or per-connection subscription limit** — track subscriptions per remote address and reject excess requests.
3. **Set a server-wide connection limit** — configure `NettyServerBuilder.maxConnectionAge` / `maxConnectionIdle` and a total connection cap to bound the attack surface at the transport layer.
4. **Require authentication** — even lightweight token-based auth raises the bar significantly for unauthenticated flooding.

### Proof of Concept

```bash
# Open 200 connections, each with 5 concurrent subscribeTopic streams = 1000 active subscriptions
# Uses grpcurl; repeat in parallel with xargs or a script

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":1}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe the Gauge via Prometheus/Actuator:
# GET http://<mirror-node-host>:8080/actuator/prometheus
# hiero_mirror_grpc_subscribers{type="TopicMessage",...} 1000.0
#
# Server thread pool / DB connection pool exhaustion follows as N grows.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L51-56)
```java
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L50-52)
```java
        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
```
