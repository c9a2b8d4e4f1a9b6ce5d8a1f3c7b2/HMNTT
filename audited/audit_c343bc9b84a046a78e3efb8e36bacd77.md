### Title
Entity Type Oracle via Distinguishable gRPC Error Responses in `topicExists()`

### Summary
The `topicExists()` method in `TopicMessageServiceImpl` returns two semantically distinct exceptions depending on whether a queried entity ID is absent from the database (`EntityNotFoundException`) or present but of a non-topic type (`IllegalArgumentException`). These map to different gRPC status codes (`NOT_FOUND` vs `INVALID_ARGUMENT`) that are visible to any unauthenticated caller, enabling systematic enumeration of entity existence and type classification across the mirror node's entity namespace.

### Finding Description
**Exact code location:** `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `topicExists()`, lines 94–106.

```
private Mono<?> topicExists(TopicMessageFilter filter) {
    var topicId = filter.getTopicId();
    return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
            .switchIfEmpty(
                    grpcProperties.isCheckTopicExists()
                            ? Mono.error(new EntityNotFoundException(topicId))   // path A
                            : Mono.just(Entity.builder()...))
            .filter(e -> e.getType() == EntityType.TOPIC)
            .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));  // path B
}
```

**Root cause:** The method takes two structurally different code paths for two distinct negative outcomes and propagates them as different exception types. The failed assumption is that callers cannot distinguish these two error conditions — they can, because `ProtoUtil.toStatusRuntimeException()` maps them to different gRPC status codes:

- `EntityNotFoundException` → `Status.NOT_FOUND` + `"0.0.X does not exist"` (entity absent from DB)
- `IllegalArgumentException` → `Status.INVALID_ARGUMENT` + `"Not a valid topic"` (entity present, wrong type)

**Exploit flow:**
1. Attacker calls `subscribeTopic()` (the public gRPC `ConsensusService/subscribeTopic` RPC) with an arbitrary `topicId`.
2. If the response is `Status.NOT_FOUND`: entity ID does not exist in the mirror node's entity table.
3. If the response is `Status.INVALID_ARGUMENT` with message `"Not a valid topic"`: entity ID exists and is a non-topic entity (ACCOUNT, CONTRACT, FILE, TOKEN, etc.).
4. If the stream opens (or hangs waiting for messages): entity ID is a valid topic.
5. Repeat across the full numeric ID space to build a complete map of which IDs exist and which are non-topic entities.

**Why existing checks are insufficient:** The `checkTopicExists` flag (default `true`) only controls whether a missing entity raises an error at all — it does not unify the error surface. When `checkTopicExists=true` (the default production setting), both error paths are active and distinguishable. There is no authentication or rate-limiting on the gRPC endpoint that would prevent automated scanning. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
An attacker can enumerate the mirror node's entire entity namespace without credentials, learning: (a) which numeric entity IDs are present in the mirror node's database, and (b) which of those are non-topic entities. On a partial mirror node (one that mirrors only a subset of the network), this reveals the operator's selective ingestion policy — information that is not otherwise public. On a full mirror node, it still leaks entity type classification at scale without any API key or authentication. The gRPC `subscribeTopic` endpoint is the only public surface needed; no privileged access is required. [4](#0-3) 

### Likelihood Explanation
The attack requires zero privileges and zero authentication. The gRPC port (default 5600) is publicly exposed. The oracle is deterministic and fast — each probe is a single RPC call that returns immediately with an error. The full Hedera entity ID space is sequential integers, making automated scanning trivial with a simple loop. The behavior is confirmed by the existing test suite itself, which explicitly asserts the two different exception types for the two cases. [5](#0-4) 

### Recommendation
Unify the two negative error paths into a single indistinguishable response. Specifically:

1. When an entity is found but is not of type `TOPIC`, throw `EntityNotFoundException` (same as the "not found" case) rather than `IllegalArgumentException`. This collapses both negative outcomes into a single `Status.NOT_FOUND` response with identical messaging.
2. Alternatively, return a generic `Status.NOT_FOUND` with a fixed, non-discriminating message (e.g., `"Topic not found"`) for both cases, regardless of whether the entity is absent or of the wrong type.
3. Do not include the entity ID in the error message text if it can be used to confirm existence.

The fix is in `topicExists()` at line 105: replace `new IllegalArgumentException("Not a valid topic")` with `new EntityNotFoundException(topicId)`. [6](#0-5) 

### Proof of Concept
```python
import grpc
from com.hederahashgraph.api.proto.java import ConsensusService_pb2_grpc, mirror_pb2

channel = grpc.insecure_channel("mirror-node-host:5600")
stub = ConsensusService_pb2_grpc.ConsensusServiceStub(channel)

for entity_num in range(1, 10000):
    request = mirror_pb2.ConsensusTopicQuery()
    request.topicID.topicNum = entity_num
    try:
        next(stub.subscribeTopic(request))
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            print(f"0.0.{entity_num}: does not exist")
        elif e.code() == grpc.StatusCode.INVALID_ARGUMENT and "Not a valid topic" in e.details():
            print(f"0.0.{entity_num}: EXISTS, non-topic entity (account/contract/file/token)")
        # else: valid topic or other error
```

Sending `subscribeTopic` with `topicID=0.0.X` for any non-topic entity (e.g., an account) returns `INVALID_ARGUMENT / "Not a valid topic"`, while a non-existent ID returns `NOT_FOUND / "0.0.X does not exist"`. The two responses are structurally distinct and machine-readable, enabling full entity-type mapping with no credentials.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-92)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/util/ProtoUtil.java (L44-60)
```java
    public static StatusRuntimeException toStatusRuntimeException(Throwable t) {
        if (Exceptions.isOverflow(t)) {
            return clientError(t, Status.DEADLINE_EXCEEDED, OVERFLOW_ERROR);
        } else if (t instanceof ConstraintViolationException
                || t instanceof IllegalArgumentException
                || t instanceof InvalidEntityException) {
            return clientError(t, Status.INVALID_ARGUMENT, t.getMessage());
        } else if (t instanceof EntityNotFoundException) {
            return clientError(t, Status.NOT_FOUND, t.getMessage());
        } else if (t instanceof TransientDataAccessException || t instanceof TimeoutException) {
            return serverError(t, Status.RESOURCE_EXHAUSTED, DB_ERROR);
        } else if (t instanceof NonTransientDataAccessResourceException) {
            return serverError(t, Status.UNAVAILABLE, DB_ERROR);
        } else {
            return serverError(t, Status.UNKNOWN, UNKNOWN_ERROR);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/service/TopicMessageServiceTest.java (L121-153)
```java
    @Test
    void topicNotFound() {
        var filter = TopicMessageFilter.builder().topicId(EntityId.of(999L)).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .thenAwait(WAIT)
                .expectError(EntityNotFoundException.class)
                .verify(WAIT);
    }

    @Test
    void topicNotFoundWithCheckTopicExistsFalse() {
        grpcProperties.setCheckTopicExists(false);
        var filter = TopicMessageFilter.builder().topicId(EntityId.of(999L)).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .expectSubscription()
                .expectNoEvent(WAIT)
                .thenCancel()
                .verify(WAIT);

        grpcProperties.setCheckTopicExists(true);
    }

    @Test
    void invalidTopic() {
        domainBuilder.entity(e -> e.type(EntityType.ACCOUNT)).block();
        var filter = TopicMessageFilter.builder().topicId(TOPIC_ID).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .thenAwait(WAIT)
                .expectError(IllegalArgumentException.class)
                .verify(Duration.ofMillis(100));
```
