### Title
Unbounded Indefinite `subscribeTopic` Streams Enable Resource Exhaustion DoS via Missing Server-Side Timeout

### Summary
The `grpcServerConfigurer` bean in `GrpcConfiguration.java` configures the `NettyServerBuilder` with only a per-connection call concurrency cap (`maxConcurrentCallsPerConnection=5`) and a shared executor, but sets no server-side call deadline, `maxConnectionAge`, or `maxConnectionIdle`. A `subscribeTopic` call with `limit=0` and no `consensusEndTime` produces a reactive stream that runs indefinitely with no server-enforced termination. An unprivileged attacker can open many connections, each saturating all 5 concurrent-call slots with permanent streams, exhausting the shared thread pool and listener subscriptions and denying service to legitimate subscribers.

### Finding Description

**Exact code path:**

`GrpcConfiguration.java` lines 28–35 — the only `NettyServerBuilder` customizations are executor assignment and the per-connection call cap:

```java
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

No `serverBuilder.maxConnectionAge(...)`, `serverBuilder.maxConnectionIdle(...)`, `serverBuilder.keepAliveTimeout(...)`, or any per-call deadline is set.

**Root cause — indefinite stream path:**

In `TopicMessageServiceImpl.subscribeTopic()` (lines 72–85), when `filter.getEndTime() == null` and `filter.hasLimit() == false` (i.e., `limit=0`):

- `pastEndTime()` (lines 123–131) returns `Flux.never()` — the takeUntil signal never fires.
- The `takeWhile` and `take()` guards are skipped entirely.
- The live branch (`incomingMessages` → `topicListener.listen()`) waits indefinitely for new messages.

The proto definition (`consensus_service.proto` lines 23–25) explicitly documents this: *"If not set or set to zero it will return messages indefinitely."*

**Why existing checks are insufficient:**

- `hiero.mirror.grpc.retriever.timeout = 60s` applies only to the historical retriever's inter-emission gap, not to the live listener phase.
- `maxConcurrentCallsPerConnection=5` is a **per-connection** cap — it does not limit the total number of connections or global concurrent streams.
- The only `ServerInterceptor` (`GrpcInterceptor.java` lines 13–22) only sets an `EndpointContext` for table-usage tracking; it enforces no rate limit or deadline.
- The `ThrottleConfiguration` / `ThrottleManagerImpl` rate-limiting exists only in the `web3` module — there is no equivalent in the `grpc` module.
- No authentication or authorization is required to call `subscribeTopic`.

### Impact Explanation

Each indefinite stream holds:
- A slot in `maxConcurrentCallsPerConnection` (blocking other callers on the same connection)
- A subscription in the shared `topicListener` (Redis/poll listener), consuming listener buffer slots (`maxBufferSize=16384`)
- A `TopicContext` object and associated reactive pipeline in memory
- Periodic `boundedElastic` scheduler tasks (safety-check polling every 1 second)

An attacker opening *N* connections × 5 streams each can exhaust the `applicationTaskExecutor` thread pool, the `boundedElastic` scheduler's thread ceiling, and listener buffer capacity, causing `RESOURCE_EXHAUSTED` errors or silent stream stalls for all legitimate subscribers. This is a complete Denial-of-Service against the HCS `subscribeTopic` API.

### Likelihood Explanation

- **No privileges required:** The gRPC port (5600) is publicly accessible with no authentication.
- **Trivially scriptable:** A single `grpcurl` or gRPC client loop opens connections and fires `subscribeTopic` with `{"topicID": {"topicNum": 1}}` (limit omitted = 0, endTime omitted = indefinite).
- **Persistent:** Without `maxConnectionAge` or `maxConnectionIdle`, streams survive indefinitely even if the attacker's client goes silent (half-open TCP).
- **Repeatable:** After a server restart, the attack can be re-launched immediately.
- **Low cost:** Each stream is reactive/non-blocking on the attacker side; a single attacker process can hold hundreds of connections.

### Recommendation

1. **Add server-side call deadline / max connection age** in `grpcServerConfigurer`:
   ```java
   serverBuilder.maxConnectionAge(1, TimeUnit.HOURS);
   serverBuilder.maxConnectionAgeGrace(30, TimeUnit.SECONDS);
   serverBuilder.maxConnectionIdle(5, TimeUnit.MINUTES);
   serverBuilder.keepAliveTimeout(20, TimeUnit.SECONDS);
   ```
2. **Enforce a maximum stream lifetime** via a `ServerInterceptor` that sets a deadline on all incoming calls, or via a Reactor `timeout()` operator in `TopicMessageServiceImpl.subscribeTopic()` (e.g., `flux.timeout(Duration.ofHours(1))`).
3. **Add per-IP connection rate limiting** in the gRPC module analogous to the `ThrottleConfiguration` in `web3`.
4. **Expose `maxConcurrentCallsPerConnection` as a global (not per-connection) limit** or add a global concurrent-stream counter with a configurable ceiling.
5. **Add `NettyProperties` fields** for `maxConnectionAge` and `maxConnectionIdle` so operators can tune them without code changes.

### Proof of Concept

```bash
# Open 10 connections, each with 5 indefinite subscribeTopic streams (50 total)
for i in $(seq 1 10); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}}' \
      localhost:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Now attempt a legitimate subscription — it will receive RESOURCE_EXHAUSTED
# or hang indefinitely as the thread pool / listener buffer is saturated
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 41110}, "limit": 1}' \
  localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

Observe: the legitimate call either blocks indefinitely, returns `RESOURCE_EXHAUSTED`, or the server's `hiero.mirror.grpc.subscribers` gauge climbs to the attacker-controlled value with no server-side eviction.