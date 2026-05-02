### Title
Deleted Topic's `customFees` Field Incorrectly Populated in Mirror Node REST API Response

### Summary
The `getTopic()` handler in `TopicController` unconditionally fetches and returns `customFees` for any topic, including deleted ones, without suppressing or nulling the fee data when `entity.deleted == true`. Any unauthenticated external user can query `GET /api/v1/topics/{id}` for a deleted topic and receive a response where `custom_fees` is populated with active-looking fee entries alongside `"deleted": true`, creating a misleading and incorrect protocol-level record.

### Finding Description
**Exact code path:**

In `TopicController.getTopic()` (lines 32–37), three independent service calls are made and their results are passed directly to the mapper:

```java
var topic = topicService.findById(id.id());
var entity = entityService.findById(id.id());
var customFee = customFeeService.findById(id.id());
return topicMapper.map(customFee, entity, topic);
```

`CustomFeeServiceImpl.findById()` (lines 19–23) calls `customFeeRepository.findById(id.getId())` — a plain Spring Data `CrudRepository.findById()` with no deleted-status filter:

```java
return customFeeRepository
        .findById(id.getId())
        .orElseThrow(() -> new EntityNotFoundException("Custom fee for entity not found"));
```

`EntityServiceImpl.findById()` (lines 24–27) similarly uses `entityRepository.findById(id.getId())` — the standard `CrudRepository` method that returns the entity regardless of its `deleted` column value.

`TopicMapper` (line 16) maps `customFee` directly to `customFees` with no conditional suppression:

```java
@Mapping(source = "customFee", target = "customFees")
```

**Root cause:** There is no guard anywhere in the controller, service, or mapper that checks `entity.getDeleted() == true` before including `customFees` in the response. The `custom_fee` table row for a deleted topic is never cleared on deletion (the `ConsensusDeleteTopicTransactionHandler` only sets `deleted=true` on the `entity` row), so the fee data persists and is returned verbatim.

**Why existing checks fail:** The `entity.deleted` field is mapped to `Topic.deleted` in the response, so the response does include `"deleted": true`. However, this is purely informational — the mapper does not use it to suppress `customFees`. No service layer check gates the `customFeeService.findById()` call on the entity's deletion status.

### Impact Explanation
Any unauthenticated caller receives a response for a deleted topic that contains a fully populated `custom_fees` object (with `created_timestamp` and `fixed_fees` entries) alongside `"deleted": true`. This is an incorrect mirror node record: the exported state implies active fees on a topic that no longer exists on the network. Applications or downstream consumers that do not explicitly check `deleted` before consuming `custom_fees` will operate on stale, invalid fee schedules. In a protocol context where mirror node data is treated as authoritative for fee discovery, this constitutes an integrity violation in the exported record.

### Likelihood Explanation
Exploitation requires zero privileges — the endpoint is public and unauthenticated. Any user who knows or can enumerate a deleted topic ID can trigger this. Topic IDs are sequential and publicly observable on-chain, making enumeration trivial. The condition (a topic with custom fees that was subsequently deleted) is a normal lifecycle event, not a rare edge case.

### Recommendation
In `getTopic()`, after fetching the entity, check `entity.getDeleted()` and either:
1. Return a 404 (consistent with how other APIs treat deleted entities), or
2. Conditionally pass `null` as the `customFee` argument to `topicMapper.map()` when `entity.getDeleted() == Boolean.TRUE`, so the mapper emits a null/empty `custom_fees` field.

The mapper itself should also be updated to treat a null `customFee` as an empty `ConsensusCustomFees` object rather than propagating stale fee data.

### Proof of Concept
1. Create a topic with a custom fee schedule via `ConsensusCreateTopic`.
2. Delete the topic via `ConsensusDeleteTopic`.
3. Wait for the mirror node to ingest both transactions.
4. As an unauthenticated user, call:
   ```
   GET /api/v1/topics/{deleted_topic_id}
   ```
5. Observe the response contains `"deleted": true` **and** a populated `"custom_fees"` object with non-empty `fixed_fees`, incorrectly representing active fees on a deleted topic. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L24-27)
```java
    public Entity findById(EntityId id) {
        return entityRepository.findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Entity not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/mapper/TopicMapper.java (L16-21)
```java
    @Mapping(source = "customFee", target = "customFees")
    @Mapping(source = "entity.autoRenewAccountId", target = "autoRenewAccount")
    @Mapping(source = "entity.createdTimestamp", target = "createdTimestamp", qualifiedByName = QUALIFIER_TIMESTAMP)
    @Mapping(source = "entity.id", target = "topicId")
    @Mapping(source = "entity.timestampRange", target = "timestamp")
    Topic map(CustomFee customFee, Entity entity, org.hiero.mirror.common.domain.topic.Topic topic);
```
