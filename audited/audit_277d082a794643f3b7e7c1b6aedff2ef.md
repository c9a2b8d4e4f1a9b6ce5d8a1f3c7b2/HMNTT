### Title
Unbounded Request Body Allocation in `estimateFees()` Enables Unauthenticated DoS via OOM

### Summary
The `POST /api/v1/network/fees` endpoint in `NetworkController.java` accepts a raw binary protobuf body with no size constraint. Spring MVC reads the entire HTTP body into a heap-allocated `byte[]` before the controller method executes, and no Tomcat `maxPostSize` or custom filter limits non-form binary payloads. An unauthenticated attacker can POST an arbitrarily large body to exhaust JVM heap memory and crash the service.

### Finding Description
**Exact code path:**

In `NetworkController.java` lines 113–124, the `estimateFees()` method is declared as:

```java
@PostMapping(
        consumes = {"application/protobuf", "application/x-protobuf"},
        value = "/fees")
FeeEstimateResponse estimateFees(
        @RequestBody @NotNull byte[] body,   // ← no @Size, no length cap
        ...
``` [1](#0-0) 

Spring MVC resolves `@RequestBody byte[]` via `ByteArrayHttpMessageConverter`, which calls `StreamUtils.copyToByteArray(inputStream)` — reading the entire HTTP body into a single heap `byte[]` with no size guard. Only after this allocation does the controller receive `body` and call:

```java
final var transaction = Transaction.PROTOBUF.parse(Bytes.wrap(body));
```

`Bytes.wrap(body)` is a zero-copy wrapper, but the prior `byte[]` allocation is already unbounded. The protobuf parse then performs additional heap allocations proportional to the payload.

**Root cause:** The only validation annotation present is `@NotNull`, which checks for a null reference but imposes no upper bound on array length. There is no `@Size(max = ...)` on the `body` parameter, no Spring `ContentSizeLimitingInputStream`, no custom servlet filter, and no Tomcat `server.tomcat.max-http-form-post-size` configuration applicable to `application/protobuf` content (Tomcat's `maxPostSize` only restricts `application/x-www-form-urlencoded` form data, not arbitrary binary bodies).

**Configuration evidence:** The only file in `rest-java/src/main/resources/` is `banner.txt` — no `application.yml` exists, confirming no Spring Boot body-size properties are set. [2](#0-1) 

### Impact Explanation
A single HTTP request carrying a multi-gigabyte body causes the JVM to attempt allocating a `byte[]` of that size. If heap is exhausted, the JVM throws `OutOfMemoryError`, crashing the `rest-java` service process entirely. Because the endpoint is unauthenticated and publicly reachable (it is a public fee-estimation API), repeated requests can keep the service unavailable. All other endpoints served by the same process (exchange rates, nodes, stake, supply) are also taken offline. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation
The endpoint is intentionally public — it requires no API key, session token, or authentication header. Any attacker with network access can send a single `curl` command with a large body. The attack is trivially repeatable, requires no special knowledge of the protocol, and can be scripted to fire continuously. Modern HTTP clients and load-testing tools make generating multi-GB POST bodies straightforward.

### Recommendation
Apply a defense-in-depth combination:

1. **Controller-level:** Add a `@Size(max = MAX_TX_BYTES)` constraint on the `body` parameter (Hedera's maximum transaction size is 6 KB; a safe ceiling is ~64 KB):
   ```java
   @RequestBody @NotNull @Size(max = 65536) byte[] body
   ```

2. **Servlet filter (preferred for early rejection):** Register a `ContentSizeLimitingInputStream`-based filter or use Spring's `CommonsRequestLoggingFilter` pattern to reject oversized bodies before Spring MVC reads them, returning HTTP 413.

3. **Tomcat configuration:** Set `server.tomcat.max-swallow-size` and add a custom `TomcatConnectorCustomizer` that limits the maximum request body size for all non-multipart requests.

4. **Nginx/ingress layer:** Enforce `client_max_body_size 64k;` at the reverse proxy to reject oversized requests before they reach the JVM.

### Proof of Concept
```bash
# Generate a 512 MB payload and POST it to the fees endpoint
dd if=/dev/zero bs=1M count=512 | \
  curl -s -o /dev/null -w "%{http_code}" \
       -X POST \
       -H "Content-Type: application/protobuf" \
       --data-binary @- \
       http://<mirror-node-host>:<port>/api/v1/network/fees

# Repeat in a loop to sustain OOM pressure:
while true; do
  dd if=/dev/zero bs=1M count=512 2>/dev/null | \
    curl -s -o /dev/null -X POST \
         -H "Content-Type: application/protobuf" \
         --data-binary @- \
         http://<mirror-node-host>:<port>/api/v1/network/fees &
done
```

Expected result: JVM heap exhaustion → `OutOfMemoryError` → process crash → service unavailable for all endpoints.

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

**File:** rest-java/src/main/resources/banner.txt (L1-1)
```text

```
