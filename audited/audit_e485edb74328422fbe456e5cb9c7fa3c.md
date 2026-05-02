### Title
`getTopic()` Returns HTTP 404 for Valid Topics Without Custom Fees, Masking Their Existence

### Summary
`TopicController.getTopic()` unconditionally calls `customFeeService.findById()`, which throws `jakarta.persistence.EntityNotFoundException` whenever no custom fee record exists for the requested topic. Since custom fees are entirely optional in `ConsensusCreateTopic` transactions, any topic created without custom fees will cause `getTopic()` to return HTTP 404 — the same response as a genuinely non-existent topic — to any unprivileged caller.

### Finding Description

**Exact code path:**

`TopicController.getTopic()` (lines 32–37) calls three services in sequence with no error isolation:

```java
var topic = topicService.findById(id.id());      // line 33 – succeeds for valid topic
var entity = entityService.findById(id.id());    // line 34 – succeeds for valid topic
var customFee = customFeeService.findById(id.id()); // line 35 – THROWS if no custom fee
``` [1](#0-0) 

`CustomFeeServiceImpl.findById()` (line 22) unconditionally throws on a missing record:

```java
.orElseThrow(() -> new EntityNotFoundException("Custom fee for entity not found"));
``` [2](#0-1) 

`GenericControllerAdvice.notFound()` (line 116) maps every `EntityNotFoundException` — regardless of which service threw it — to HTTP `404 NOT_FOUND`:

```java
private ResponseEntity<Object> notFound(final EntityNotFoundException e, final WebRequest request) {
    return handleExceptionInternal(e, null, null, NOT_FOUND, request);
}
``` [3](#0-2) 

**Root cause / failed assumption:** The code assumes every topic has a corresponding `custom_fee` row. This is false — custom fees are an optional field in `ConsensusCreateTopic`. Topics created without custom fees have no row in the `custom_fee` table, so `customFeeRepository.findById()` returns `Optional.empty()`, triggering the throw.

**Why existing checks fail:** The `GenericControllerAdvice` handler does not distinguish between "topic does not exist" (thrown by `topicService`) and "topic exists but has no custom fees" (thrown by `customFeeService`). Both produce an identical HTTP 404 response, making a valid topic indistinguishable from a non-existent one.

### Impact Explanation

Any topic created via `ConsensusCreateTopic` without custom fees is permanently inaccessible through `GET /api/v1/topics/{id}`. API consumers (wallets, explorers, dApps) receive HTTP 404 and correctly conclude the topic does not exist — which is false. This constitutes a denial of accurate ledger state information. Because custom fees are optional and likely absent for the majority of topics, the affected population is large. The mirror node's authoritative record of a valid on-chain transaction is suppressed entirely.

### Likelihood Explanation

No privileges, authentication, or special knowledge are required. Any caller who queries a topic ID that was created without custom fees triggers the bug deterministically and repeatably. The attacker does not need to create or modify any transaction; they only need to know (or enumerate) a valid topic ID. Topic IDs are sequential and publicly visible on the ledger, making enumeration trivial.

### Recommendation

Change `CustomFeeService.findById()` to return `Optional<CustomFee>` instead of throwing on absence, and update `TopicController.getTopic()` to pass the optional value to the mapper:

```java
// CustomFeeService.java
Optional<CustomFee> findById(EntityId id);

// CustomFeeServiceImpl.java
return customFeeRepository.findById(id.getId()); // return Optional directly

// TopicController.java
var customFee = customFeeService.findById(id.id()); // Optional<CustomFee>
return topicMapper.map(customFee, entity, topic);   // mapper handles empty
```

The `TopicMapper` should treat an empty `Optional` as a topic with no custom fees (e.g., an empty list), not as an error condition.

### Proof of Concept

**Precondition:** A topic exists in the mirror node database (rows in `topic` and `entity` tables) with no corresponding row in the `custom_fee` table. This is the normal state for any `ConsensusCreateTopic` transaction submitted without custom fees.

**Steps:**
1. Identify or create a topic without custom fees (e.g., topic ID `0.0.12345`).
2. Send an unauthenticated HTTP GET request:
   ```
   GET /api/v1/topics/0.0.12345
   ```
3. **Expected (correct) response:** HTTP 200 with topic data and an empty `custom_fees` array.
4. **Actual response:** HTTP 404 — identical to querying a topic that was never created.

The `CustomFeeServiceTest.findByIdNotFound` test [4](#0-3) 
already confirms the throw behavior. No existing controller-level test covers the scenario of a valid topic with no custom fee row.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L32-37)
```java
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/CustomFeeServiceImpl.java (L19-23)
```java
    public CustomFee findById(EntityId id) {
        return customFeeRepository
                .findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Custom fee for entity not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java (L115-118)
```java
    @ExceptionHandler
    private ResponseEntity<Object> notFound(final EntityNotFoundException e, final WebRequest request) {
        return handleExceptionInternal(e, null, null, NOT_FOUND, request);
    }
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/service/CustomFeeServiceTest.java (L25-29)
```java
    @Test
    void findByIdNotFound() {
        var entityId = EntityId.of(10L);
        assertThatThrownBy(() -> service.findById(entityId)).isInstanceOf(EntityNotFoundException.class);
    }
```
