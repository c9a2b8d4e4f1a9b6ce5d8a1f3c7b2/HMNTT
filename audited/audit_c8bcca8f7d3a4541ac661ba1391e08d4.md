### Title
Unauthenticated Parallel Stream Flood Inflates `hiero_mirror_grpc_retriever` Monitoring Metric

### Summary
The `subscribeTopic()` gRPC endpoint has no per-user, per-IP, or global connection rate limiting. An unprivileged attacker can open an unbounded number of TCP connections, each carrying up to 5 concurrent `subscribeTopic()` calls with `startTime=0`, causing `PollingTopicMessageRetriever.retrieve()` to be invoked at arbitrary scale. Every such invocation registers a Micrometer observation under the `hiero_mirror_grpc_retriever` metric name, inflating the "Retriever Rate" shown in the operational Grafana dashboard and simultaneously amplifying database load.

### Finding Description
**Code path:**

- `ConsensusController.subscribeTopic()` — `grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java` lines 43-53 — accepts any unauthenticated gRPC call, builds a `TopicMessageFilter`, and delegates to `TopicMessageServiceImpl.subscribeTopic()` with no admission control.
- `TopicMessageServiceImpl.subscribeTopic()` — lines 59-92 — unconditionally calls `topicMessageRetriever.retrieve(filter, true)` for every subscriber; the only global state is an `AtomicLong subscriberCount` gauge that is purely informational and enforces nothing.
- `PollingTopicMessageRetriever.retrieve()` — lines 44-63 — constructs a polling `Flux`, names it `METRIC = "hiero_mirror_grpc_retriever"` (line 56), and attaches `Micrometer.observation(observationRegistry)` (line 57). Every subscription to this Flux creates a new Micrometer observation that increments `hiero_mirror_grpc_retriever_seconds_count` on each poll cycle.

**Root cause / failed assumption:** The design assumes that `maxConcurrentCallsPerConnection = 5` (`NettyProperties.java` line 14, applied in `GrpcConfiguration.java` line 33) is a sufficient admission gate. It is not: this setting limits concurrent RPC calls *per TCP connection*, but places no cap on the number of TCP connections a single client IP may open. An attacker opens N connections and issues 5 `subscribeTopic()` calls on each, yielding 5N simultaneous `retrieve()` invocations.

**Why `startTime=0` maximises impact:** `TopicMessageFilter` validates `startTime >= 0` (`@Min(0)`, line 25). A value of `0` causes `PollingTopicMessageRetriever.poll()` to query the database from the earliest stored message, maximising both the number of DB rows scanned per poll and the duration each stream remains active (until the 60-second `retrieverProperties.getTimeout()` fires or the attacker disconnects).

**Metric flooding mechanism:** The Grafana dashboard queries `rate(hiero_mirror_grpc_retriever_seconds_count[...])` to display "Retriever Rate." With 5N concurrent streams each polling every 2 seconds (throttled mode), the counter increments at 5N times the legitimate rate, making the dashboard misrepresent actual retrieval activity.

### Impact Explanation
1. **Monitoring integrity:** The `hiero_mirror_grpc_retriever_seconds_count` metric is the sole signal operators use to gauge historical-message retrieval throughput. Artificial inflation hides real anomalies (e.g., a genuine retrieval spike caused by a fee-schedule change) or triggers false-positive alerts, degrading incident-response fidelity.
2. **Database amplification:** Each stream with `startTime=0` issues repeated full-history scans against the `topic_message` table at up to `maxPageSize=1000` rows per poll, every 2 seconds. N=200 streams → 100 simultaneous DB queries per poll cycle, exhausting the HikariCP connection pool (alert threshold already defined in `charts/hedera-mirror-grpc/values.yaml` line 214 at 75% utilisation).
3. **Service degradation for legitimate subscribers:** Pool exhaustion causes legitimate `subscribeTopic()` calls to queue or fail, constituting a denial-of-service against the HCS streaming API.

Severity: **High** (unauthenticated, no preconditions, direct operational impact).

### Likelihood Explanation
- No authentication is required; the gRPC port (default 5600) is publicly reachable.
- Standard gRPC client libraries (e.g., `grpcurl`, Hedera SDK) trivially open multiple connections in a loop.
- `startTime=0` is a documented, valid filter value (used in the project's own integration tests, e.g., `TopicMessageServiceTest.java` line 304).
- The attack is repeatable and scriptable; a single commodity machine can sustain hundreds of connections.

### Recommendation
1. **Global concurrent-subscriber cap:** Add an `AtomicInteger activeRetrievals` counter in `PollingTopicMessageRetriever` or `TopicMessageServiceImpl`; reject (with `RESOURCE_EXHAUSTED` status) any `subscribeTopic()` call that would exceed a configurable ceiling.
2. **Per-IP / per-identity connection rate limiting:** Introduce a Netty `ChannelHandler` or a gRPC `ServerInterceptor` that tracks open streams per remote address and enforces a per-IP limit (e.g., 10 concurrent streams).
3. **Restrict `startTime=0` or add cost-based throttling:** Treat `startTime` values older than a configurable horizon (e.g., 24 h) as requiring elevated privilege, or apply a stricter polling frequency / smaller page size for deep-history queries.
4. **Metric cardinality guard:** Emit the `hiero_mirror_grpc_retriever` observation only after the stream completes (or sample it), so a flood of short-lived streams does not linearly inflate the rate counter.

### Proof of Concept
```bash
# Open 50 TCP connections, each with 5 concurrent subscribeTopic streams (250 total)
# pointing to a known topic with startTime=0 (all history)

for i in $(seq 1 50); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":41110},"consensusStartTime":{"seconds":0,"nanos":0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# After ~10 seconds, query Prometheus:
# rate(hiero_mirror_grpc_retriever_seconds_count[1m])
# Expected: value ~250x the baseline single-stream rate
# Legitimate retrieval rate is misrepresented; DB connection pool alert fires.
```