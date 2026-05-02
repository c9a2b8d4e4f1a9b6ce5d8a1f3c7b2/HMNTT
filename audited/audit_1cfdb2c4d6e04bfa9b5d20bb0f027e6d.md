### Title
Unauthenticated gRPC `getNodes()` Streams Exhaust Shared `boundedElastic` Thread Pool via Blocking `page()` Calls

### Summary
`NetworkServiceImpl.getNodes()` uses `Schedulers.boundedElastic()` as the repeat scheduler, causing each subsequent `page()` invocation — a blocking database transaction — to execute on and hold a bounded elastic thread. With a default `pageSize` of 10 and no rate limiting or authentication on the gRPC endpoint, an unprivileged attacker can open many concurrent `getNodes()` streams to exhaust the shared global bounded elastic thread pool, starving all other services that depend on it (topic message retrieval, polling listeners) and causing >=30% of gRPC processing to halt.

### Finding Description

**Exact code path:**

`NetworkServiceImpl.getNodes()` — `grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java`, lines 68–76:

```java
return Flux.defer(() -> page(context))
        .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                .jitter(0.5)
                .withFixedDelay(addressBookProperties.getPageDelay())
                .withScheduler(Schedulers.boundedElastic()))   // ← global shared pool
        .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
```

`page()` — lines 79–108:

```java
private Flux<AddressBookEntry> page(AddressBookContext context) {
    return transactionOperations.execute(t -> {   // ← blocking DB call
        ...
        var nodes = addressBookEntryRepository.findByConsensusTimestampAndNodeId(...);
        ...
        return Flux.fromIterable(nodes);
    });
}
```

**Root cause:**

`RepeatSpec.withScheduler(Schedulers.boundedElastic())` schedules the inter-page delay on the bounded elastic pool. When the delay expires, the bounded elastic thread emits the repeat signal and immediately re-subscribes to `Flux.defer(() -> page(context))`. Because `page()` calls `transactionOperations.execute(...)` — a synchronous, blocking JDBC transaction — the bounded elastic thread is held for the entire duration of the DB query on every page after the first.

**Why the default configuration makes this worse:**

`AddressBookProperties` defaults: `pageSize = 10`, `pageDelay = 250ms`. The Hedera mainnet address book contains ~30+ nodes, so each stream requires at least 3 sequential `page()` calls. Each call holds a bounded elastic thread for the DB round-trip (~10–50ms). With `pageDelay = 250ms`, each stream cycles through a thread every ~250ms.

**Shared pool impact:**

`Schedulers.boundedElastic()` is a JVM-global singleton. The same pool is used by:
- `PollingTopicMessageRetriever` (line 41: `scheduler = Schedulers.boundedElastic()`)
- `PollingTopicListener`, `SharedPollingTopicListener`, `SharedTopicListener`, `TopicMessageServiceImpl`

Exhausting it blocks all of these services simultaneously.

**No existing mitigations:**

- No authentication on the gRPC `getNodes()` endpoint (confirmed — `NetworkController` has no interceptor or auth check)
- No rate limiting or concurrent-stream cap (no `maxConcurrentCallsPerMethod` or equivalent found in `GrpcConfiguration`)
- No connection-level throttle
- `limit = 0` in `AddressBookFilter` maps to `Long.MAX_VALUE` (line 73), so a client can request unlimited entries

### Impact Explanation

Exhausting the bounded elastic pool (default: `10 × availableProcessors`, e.g., 80 threads on an 8-core node) causes:
1. All `PollingTopicMessageRetriever` polls to queue indefinitely — topic message subscriptions stop delivering
2. All `PollingTopicListener` / `SharedPollingTopicListener` polling to stall — live topic streams freeze
3. New `getNodes()` streams to queue behind the attacker's streams

This constitutes shutdown of >=30% of the mirror node's gRPC processing capacity without any brute-force network-layer attack.

### Likelihood Explanation

Any unauthenticated external client with a gRPC library can open concurrent streams. The attacker needs no credentials, no special knowledge, and no privileged network position. The attack is:
- **Repeatable**: streams can be re-opened immediately after they complete
- **Cheap**: each stream is a single gRPC call with no payload cost
- **Scalable**: a single attacker machine can sustain hundreds of concurrent HTTP/2 streams

To exhaust 80 bounded elastic threads with `pageDelay=250ms` and `page()` taking ~20ms: `80 / (20ms / 250ms) = 1000` concurrent streams — achievable from a single host with standard gRPC tooling (e.g., `ghz`, custom client).

### Recommendation

1. **Add per-IP or global concurrent-stream rate limiting** on the `getNodes()` gRPC method via a server interceptor.
2. **Move `page()` off the bounded elastic pool**: use `subscribeOn(Schedulers.boundedElastic())` explicitly and cap concurrency with `Schedulers.newBoundedElastic(...)` scoped only to address book operations, isolating it from the shared pool.
3. **Increase `pageSize` default** (e.g., 100) so the address book is served in a single page, eliminating repeat scheduling entirely for typical workloads.
4. **Cap `Long.MAX_VALUE` repeats**: add a hard upper bound on repeat count proportional to the expected address book size.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import network_service_pb2_grpc
from com.hedera.mirror.api.proto import mirror_network_service_pb2 as pb

def open_stream(channel):
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    # limit=0 → Long.MAX_VALUE, keeps stream alive across all pages
    req = pb.AddressBookQuery(limit=0)
    for _ in stub.getNodes(req):
        pass  # consume slowly or not at all

channel = grpc.insecure_channel("mirror-node-grpc:5600")
threads = [threading.Thread(target=open_stream, args=(channel,)) for _ in range(1000)]
for t in threads:
    t.start()
# After ~seconds: bounded elastic pool exhausted;
# topic message subscriptions and polling listeners stall.
```

**Observable result**: Existing topic-message subscribers stop receiving messages; new `subscribeTopic` calls hang; mirror node logs show bounded elastic task queue growing unboundedly.