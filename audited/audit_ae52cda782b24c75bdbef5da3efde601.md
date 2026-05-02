### Title
Information Disclosure via Raw ConstraintViolationException Message in gRPC Error Response

### Summary
`ProtoUtil.toStatusRuntimeException()` forwards the raw `ConstraintViolationException` message directly into the gRPC `Status.INVALID_ARGUMENT` description sent to the client. Because Jakarta Bean Validation messages include internal method names, parameter names, field names, and constraint details, any unprivileged caller who sends a malformed `AddressBookQuery` receives this internal metadata verbatim.

### Finding Description

**Code path:**

`NetworkController.getNodes()` at [1](#0-0)  pipes all errors through `ProtoUtil::toStatusRuntimeException` via `.onErrorMap`.

Inside `ProtoUtil.toStatusRuntimeException()`: [2](#0-1) 

`t.getMessage()` is passed verbatim to `clientError()`: [3](#0-2) 

`status.augmentDescription(message)` places that string directly into the gRPC trailer sent to the caller.

**Root cause:** No sanitization or redaction is applied to the `ConstraintViolationException` message before it is forwarded to the client.

**Trigger:** `NetworkServiceImpl` is annotated `@Validated`: [4](#0-3) 

`AddressBookFilter` carries Jakarta constraints: [5](#0-4) 

When Spring AOP validates the filter and a constraint is violated, the resulting `ConstraintViolationException` message takes the form:

```
getNodes.filter.fileId: must not be null
getNodes.filter.limit: must be greater than or equal to 0
```

This string is then returned word-for-word in the gRPC error to the caller.

**Why existing checks fail:** The `clientError` helper performs only logging; it applies no filtering or generic substitution to the message before embedding it in the gRPC status. The three exception types (`ConstraintViolationException`, `IllegalArgumentException`, `InvalidEntityException`) all share the same raw-message forwarding path with no distinction.

### Impact Explanation
An attacker learns:
- Internal service method names (`getNodes`)
- Internal parameter/field names (`filter`, `fileId`, `limit`)
- Exact validation rules and thresholds

While this is not a direct data breach, it reduces the attacker's reconnaissance cost, confirms internal API structure, and can guide further probing (e.g., crafting inputs that bypass or stress specific validated fields). Severity: **Low–Medium** (information disclosure).

### Likelihood Explanation
The gRPC endpoint requires no authentication. Any network-reachable client can send an `AddressBookQuery` proto with no `fileId` field set (the default protobuf behavior when the field is omitted) or with a negative `limit` value (protobuf `int32` is signed). This is trivially repeatable with any gRPC client tool (e.g., `grpcurl`).

### Recommendation
Replace the raw `t.getMessage()` pass-through for `ConstraintViolationException` with a fixed, generic message, the same way server-side errors use `DB_ERROR` and `UNKNOWN_ERROR`:

```java
} else if (t instanceof ConstraintViolationException
        || t instanceof IllegalArgumentException
        || t instanceof InvalidEntityException) {
    return clientError(t, Status.INVALID_ARGUMENT, "Invalid request parameters");
```

Define a named constant (e.g., `INVALID_ARGUMENT_ERROR`) analogous to `DB_ERROR` and `UNKNOWN_ERROR`. The full detail is already logged by `clientError()` server-side, so no diagnostic information is lost.

### Proof of Concept

```bash
# Send AddressBookQuery with no fileId (omitted = null after toFilter())
grpcurl -plaintext \
  -proto addressbook.proto \
  -d '{"limit": -1}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.NetworkService/getNodes
```

Expected response (gRPC status `INVALID_ARGUMENT`):
```
ERROR:
  Code: InvalidArgument
  Message: getNodes.filter.limit: must be greater than or equal to 0
```

Or with no fileId:
```
  Message: getNodes.filter.fileId: must not be null
```

Both responses expose internal class/field structure to the unauthenticated caller.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L34-38)
```java
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(networkService::getNodes)
                .map(this::toNodeAddress)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L35-36)
```java
@Validated
public class NetworkServiceImpl implements NetworkService {
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/AddressBookFilter.java (L13-19)
```java
public class AddressBookFilter {
    @NotNull
    private final EntityId fileId;

    @Min(0)
    private final int limit;
}
```
