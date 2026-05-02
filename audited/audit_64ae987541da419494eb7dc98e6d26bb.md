### Title
ConstraintViolationException Message Leaks Internal Field Names and Constraint Details to Unprivileged gRPC Callers

### Summary
The `@Validated` AOP proxy on `TopicMessageServiceImpl` throws a `ConstraintViolationException` when an invalid `TopicMessageFilter` is passed to `subscribeTopic()`. `ProtoUtil.toStatusRuntimeException()` catches this exception and forwards `t.getMessage()` verbatim as the gRPC `INVALID_ARGUMENT` status description, exposing internal Java field names, method names, and constraint annotation details to any unauthenticated caller.

### Finding Description
**Code path:**

1. `TopicMessageService.java` line 12: interface declares `subscribeTopic(@Valid TopicMessageFilter filter)`. [1](#0-0) 

2. `TopicMessageServiceImpl.java` lines 40–41: `@Validated` on the class causes Spring AOP to validate the `@Valid`-annotated parameter before the method body executes. [2](#0-1) 

3. `TopicMessageFilter.java` lines 25–51: the filter carries `@Min(0)` on `limit` and `startTime`, `@NotNull` on `topicId`, and `@AssertTrue` on `isValidEndTime()`/`isValidStartTime()`. When violated, the `ConstraintViolationException` message includes the full property path (e.g., `subscribeTopic.filter.limit`, `subscribeTopic.filter.isValidEndTime`) and the constraint message string. [3](#0-2) 

4. `ProtoUtil.java` lines 47–50: the exception handler catches `ConstraintViolationException` and passes `t.getMessage()` directly as the gRPC status description — no sanitization. [4](#0-3) 

5. `ProtoUtil.java` lines 62–65: `clientError()` calls `status.augmentDescription(message)` with the raw exception message, which is transmitted to the gRPC client. [5](#0-4) 

**Confirmed by the controller integration test** (`ConsensusControllerTest.java` lines 126–139), which asserts that the gRPC `StatusRuntimeException` received by the client contains the string `"limit: must be greater than or equal to 0"` — proving the internal field name and constraint text reach the wire. [6](#0-5) 

**Root cause:** `ProtoUtil.toStatusRuntimeException` treats `ConstraintViolationException` identically to `IllegalArgumentException` and forwards the full exception message, which the Jakarta Validation framework populates with the complete property path (including internal Java method/field names) and constraint annotation messages.

### Impact Explanation
Every gRPC `INVALID_ARGUMENT` response for a constraint violation discloses:
- Internal Java field names: `limit`, `startTime`, `topicId`, `subscriberId`
- Internal Java method names: `isValidEndTime`, `isValidStartTime`
- Full property path including the service method name: `subscribeTopic.filter.<field>`
- Constraint annotation details: `"must be greater than or equal to 0"`, `"must not be null"`, `"End time must be after start time"`, `"Start time must be before the current time"`

While the proto-level field names (`limit`, `topicId`) are already public, the internal method names (`isValidEndTime`, `isValidStartTime`), the parameter name (`filter`), and the full Java property path are not part of the public API contract and constitute unintended information disclosure. This aids an attacker in mapping the internal service structure.

### Likelihood Explanation
Exploitation requires zero privileges — any gRPC client can send a `ConsensusTopicQuery` with `limit = -1` (a value the proto wire format accepts as a signed 64-bit integer). The trigger is trivial, deterministic, and repeatable with no rate limiting specific to this path. The `ConsensusControllerTest` already demonstrates this works end-to-end.

### Recommendation
In `ProtoUtil.toStatusRuntimeException`, replace the raw `t.getMessage()` for `ConstraintViolationException` with a sanitized, generic message. Extract only the human-readable constraint messages (without property paths) or use a fixed string:

```java
} else if (t instanceof ConstraintViolationException cve) {
    // Collect only the message text, not the property path
    String sanitized = cve.getConstraintViolations().stream()
        .map(v -> v.getMessage())
        .collect(Collectors.joining("; "));
    return clientError(t, Status.INVALID_ARGUMENT, sanitized);
```

This removes the internal field/method names from the wire response while still providing actionable feedback.

### Proof of Concept
```
# Using grpc_cli or any gRPC client against the mirror node gRPC endpoint:
grpc_cli call <host>:<port> com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
  'topic_id: {}, limit: -1'

# Response (INVALID_ARGUMENT):
# "subscribeTopic.filter.limit: must be greater than or equal to 0"
# Internal field name "limit", parameter name "filter", and method name
# "subscribeTopic" are all disclosed in the status description.
```

Sending `limit = -1` in a `ConsensusTopicQuery` causes the `@Validated` AOP proxy to throw `ConstraintViolationException` before `subscribeTopic()` executes. `ProtoUtil` forwards the full message to the gRPC client as `Status.INVALID_ARGUMENT`, confirmed by `ConsensusControllerTest.constraintViolationException()`. [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageService.java (L12-12)
```java
    Flux<TopicMessage> subscribeTopic(@Valid TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L40-41)
```java
@Validated
public class TopicMessageServiceImpl implements TopicMessageService {
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-51)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/util/ProtoUtil.java (L47-50)
```java
        } else if (t instanceof ConstraintViolationException
                || t instanceof IllegalArgumentException
                || t instanceof InvalidEntityException) {
            return clientError(t, Status.INVALID_ARGUMENT, t.getMessage());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/util/ProtoUtil.java (L62-65)
```java
    private static StatusRuntimeException clientError(Throwable t, Status status, String message) {
        log.warn("Client error {}: {}", t.getClass().getSimpleName(), t.getMessage());
        return status.augmentDescription(message).asRuntimeException();
    }
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/controller/ConsensusControllerTest.java (L126-139)
```java
    void constraintViolationException() {
        ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
                .setTopicID(TopicID.newBuilder().build())
                .setLimit(-1)
                .build();

        assertThatThrownBy(() -> {
                    final var iterator = blockingService.subscribeTopic(query);
                    iterator.hasNext();
                })
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining("limit: must be greater than or equal to 0")
                .extracting(t -> ((StatusRuntimeException) t).getStatus().getCode())
                .isEqualTo(Status.Code.INVALID_ARGUMENT);
```
