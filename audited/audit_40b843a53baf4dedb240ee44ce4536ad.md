### Title
Unauthenticated Fee Estimation Endpoint Triggers Uncached Double DB Query Per Request via FeeTopicStore

### Summary
The public `POST /api/v1/network/fees?mode=STATE` endpoint accepts arbitrary protobuf transactions with no authentication or rate limiting. When a `ConsensusSubmitMessage` transaction is submitted, `FeeTopicStore.getTopic()` issues two sequential database queries per call — one to `TopicRepository.findById()` and one to `CustomFeeRepository.findById()` — with no caching at any layer. Any unprivileged external user can flood this endpoint to amplify database load at a 2:1 ratio compared to a single topic lookup.

### Finding Description
**Exact code path:**

`NetworkController.estimateFees()` (lines 110–124) accepts any protobuf body with no authentication or rate-limiting annotation. When `mode=STATE`, it calls `FeeEstimationService.estimateFees()` which constructs a `FeeEstimationFeeContext` (line 119 of `FeeEstimationService.java`) backed by the singleton `FeeTopicStore`.

The fee calculator invokes `FeeTopicStore.getTopic()` (lines 28–33 of `FeeTopicStore.java`) for `ConsensusSubmitMessage` transactions:

```java
// FeeTopicStore.java:28-33
public Topic getTopic(@NonNull final TopicID id) {
    return topicRepository
            .findById(id.topicNum())                          // DB query 1
            .map(topic -> toTopic(id, topic, customFeeRepository))
            .orElse(null);
}
// toTopic → getCustomFees → customFeeRepository.findById(topicId)  // DB query 2
```

`TopicRepository` is a plain `CrudRepository<Topic, Long>` with no `@Cacheable` or any caching decoration. `getCustomFees()` (lines 51–58) unconditionally calls `customFeeRepository.findById()` whenever the topic exists. There is no per-request, per-topic, or shared cache anywhere in this call chain.

**Root cause:** `FeeTopicStore` is intentionally designed to read live from the database on every call (confirmed by the test comment at `FeeEstimationServiceTest.java:361`: *"store reads live from DB, no refresh needed"*), but no compensating control (caching, rate limiting, or authentication) exists on the public endpoint that drives it.

**Why checks fail:** A grep across all of `rest-java/src/main/java/` finds zero uses of `@Cacheable`, `RateLimiter`, `@PreAuthorize`, or `@Secured`. The only filters registered are `LoggingFilter` and `MetricsFilter` — neither enforces any request throttle.

### Impact Explanation
Each `POST /api/v1/network/fees?mode=STATE` request carrying a `ConsensusSubmitMessage` targeting a valid topic causes exactly 2 synchronous database round-trips (topic row + custom fee row) with no result reuse across requests. An attacker sending N concurrent requests generates 2N database queries. At sufficient volume this saturates the database connection pool, degrades query latency for all other mirror node consumers (REST, gRPC, importer), and can render the mirror node unresponsive. There is no economic cost to the attacker and no impact on the Hedera consensus network itself — the damage is confined to mirror node infrastructure availability.

### Likelihood Explanation
The exploit requires zero privileges, zero tokens, and zero on-chain activity. The attacker needs only a valid topic ID (obtainable from any public mirror node query) and the ability to send HTTP POST requests. The attack is trivially scriptable, repeatable at any rate, and requires no special knowledge beyond the public OpenAPI spec. The `mode=STATE` parameter is documented and defaults to `INTRINSIC`, so an attacker must explicitly set it, but this is a one-line change.

### Recommendation
1. **Add per-topic caching in `FeeTopicStore.getTopic()`** using a short-lived (e.g., 5–30 second) Caffeine or Spring `@Cacheable` cache keyed on `topicNum`. This eliminates the repeated DB hit for the same topic across concurrent requests.
2. **Add rate limiting on `POST /api/v1/network/fees`** (e.g., via a servlet filter or Spring's `@RateLimiter`) to bound the number of requests per IP per second.
3. **Consider requiring `mode=STATE` to be gated** behind a documented advisory that it incurs live DB reads, or restrict it to authenticated callers.

### Proof of Concept
**Preconditions:** Mirror node is running; at least one topic exists (e.g., topic ID `0.0.1234`).

**Steps:**
1. Construct a protobuf-encoded `ConsensusSubmitMessage` transaction targeting topic `0.0.1234`.
2. Send it in a tight loop:
   ```bash
   while true; do
     curl -s -X POST "https://<mirror-node>/api/v1/network/fees?mode=STATE" \
       -H "Content-Type: application/x-protobuf" \
       --data-binary @submit_msg.bin &
   done
   ```
3. Each concurrent request triggers `topicRepository.findById(1234)` + `customFeeRepository.findById(1234)` with no caching.
4. Observe database connection pool exhaustion and rising query latency on the mirror node.

**Relevant code locations:**
- `rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java` lines 110–124 (unauthenticated endpoint)
- `rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeTopicStore.java` lines 28–58 (double DB query, no cache)
- `rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java` lines 1–8 (plain `CrudRepository`, no cache)