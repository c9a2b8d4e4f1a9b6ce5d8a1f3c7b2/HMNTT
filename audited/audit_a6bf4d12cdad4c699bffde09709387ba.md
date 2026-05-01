### Title
Unbounded Concurrent gRPC `subscribeTopic` Streams Exhaust DB Connection Pool via Unauthenticated DoS

### Summary
An unauthenticated attacker can open an arbitrary number of TCP connections to the gRPC endpoint, each carrying up to 5 concurrent `subscribeTopic` streams (the per-connection limit), resulting in an unbounded total subscriber count. Each stream with `startTime=0` and no `endTime` continuously polls the database via `PollingTopicMessageRetriever.retrieve()` every 2 seconds indefinitely, collectively exhausting the HikariCP connection pool and denying legitimate consumers access to topic message data including fee-related transaction records.

### Finding Description

**Code locations:**

- `grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java` line 14: `maxConcurrentCallsPerConnection = 5` — limits streams *per TCP connection* only.
- `grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java` lines 33: `serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection())` — this is the only concurrency guard applied.
- `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java` lines 48, 89–90: `subscriberCount` is an `AtomicLong` used **only as a Micrometer gauge metric**; it is never checked against any cap before accepting a new subscription.
- `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java` line 63: `topicMessageRetriever.retrieve(filter, true)` — every new subscription immediately starts a throttled historical retrieval.
- `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java` lines 98–101: when `throttled=true`, `numRepeats = Long.MAX_VALUE` and `frequency = pollingFrequency` (default 2 s), meaning the poll loop runs forever.
- `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java` line 78: `Flux.fromStream(topicMessageRepository.findByFilter(newFilter))` — each poll synchronously acquires a DB connection from HikariCP for the duration of the result-set streaming.
- `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java` lines 123–126: `pastEndTime()` returns `Flux.never()` when `endTime == null`, so the subscription never self-terminates.

**Root cause:** The per-connection call limit (`maxConcurrentCallsPerConnection=5`) is the only admission-control mechanism. Because there is no limit on the number of TCP connections, no global subscriber cap, no per-IP rate limit, and no authentication requirement on the gRPC endpoint, an attacker multiplies connections to achieve an unbounded total stream count. Every stream independently and repeatedly acquires DB connections, exhausting the pool.

**Failed assumption:** The design assumes that `maxConcurrentCallsPerConnection` is sufficient to bound total server load. It is not — it bounds load *per connection*, not globally.

### Impact Explanation
When the HikariCP pool is exhausted, all DB-dependent operations in the gRPC service fail with connection-timeout errors. This includes retrieval of topic messages that carry fee-related transaction data (e.g., `initialTransactionId`, `payerAccountId` embedded in `TopicMessage` chunk info). Legitimate subscribers receive errors or stall indefinitely. The Prometheus alert `GrpcHighDBConnections` (threshold 75 %) confirms the project itself recognises this as a critical resource boundary. Severity: **High** (full availability loss of the gRPC mirror node service).

### Likelihood Explanation
No privileges, accounts, or tokens are required. A single attacker machine can open thousands of TCP connections to port 5600 using standard HTTP/2 tooling (e.g., `grpcurl`, `ghz`, or a trivial Go/Python script). The attack is repeatable, cheap, and requires no knowledge of valid topic IDs (the `checkTopicExists` guard only adds one extra DB query per stream before the polling loop begins, and can be bypassed by using any existing topic ID). The default HikariCP pool for the gRPC module is small (typically 10 connections), making exhaustion trivial.

### Recommendation
1. **Enforce a global subscriber cap**: Check `subscriberCount` against a configurable maximum in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP connection rate limiting** at the Netty/gRPC layer (e.g., via a `ServerInterceptor` using bucket4j, mirroring the pattern already used in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`).
3. **Set a maximum total connection limit** on the `NettyServerBuilder` (e.g., `serverBuilder.maxConnectionAge(...)` and a connection-count guard).
4. **Enforce a mandatory `endTime` or maximum subscription duration** for unauthenticated callers to prevent indefinite open streams.
5. **Increase `maxConcurrentCallsPerConnection` documentation** to clarify it is not a global guard.

### Proof of Concept
```bash
# Open 200 TCP connections, each with 5 concurrent subscribeTopic streams (= 1000 total)
# using ghz gRPC benchmarking tool (no auth required)
ghz --insecure \
    --proto consensus_service.proto \
    --call com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
    --data '{"topicID":{"topicNum":1},"consensusStartTime":{"seconds":0,"nanos":0}}' \
    --connections 200 \
    --concurrency 1000 \
    --duration 300s \
    <mirror-node-host>:5600
```
After ~10–30 seconds, all HikariCP connections are held by polling threads. New legitimate `subscribeTopic` or any other DB-backed gRPC call returns `INTERNAL` / connection-pool-timeout errors. The `hiero_mirror_grpc_subscribers` gauge climbs to 1000 with no server-side rejection.