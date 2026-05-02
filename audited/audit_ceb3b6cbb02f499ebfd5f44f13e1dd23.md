### Title
Information Disclosure via ConstraintViolationException Message Leaked to gRPC Clients on Missing fileId

### Summary
Any unauthenticated gRPC client can omit `fileId` from an `AddressBookQuery` request, causing `toFilter()` to build an `AddressBookFilter` with a `null` fileId. Spring's `@Validated`/`@Valid` AOP then throws a `ConstraintViolationException` whose raw `.getMessage()` — containing internal method, parameter, and field names — is forwarded verbatim to the caller via `ProtoUtil.toStatusRuntimeException()`.

### Finding Description

**Code path:**

1. `NetworkController.toFilter()` only sets `fileId` when `query.hasFileId()` is true: [1](#0-0) 

   When `fileId` is absent, `filter.build()` produces an `AddressBookFilter` with `fileId = null`.

2. `AddressBookFilter.fileId` carries `@NotNull`: [2](#0-1) 

3. `NetworkService.getNodes()` declares `@Valid` on its parameter: [3](#0-2) 

   and `NetworkServiceImpl` is annotated `@Validated`: [4](#0-3) 

   Together these cause Spring AOP to throw a `ConstraintViolationException` with a message of the form:
   ```
   getNodes.addressBookFilter.fileId: must not be null
   ```

4. The error handler passes `t.getMessage()` directly as the gRPC status description: [5](#0-4) 

   No sanitization occurs before the message is sent to the client.

**Root cause:** `toFilter()` silently produces a null `fileId` for any request that omits the field, and the downstream validation error message is returned verbatim to the caller.

### Impact Explanation

The gRPC status description returned to the client discloses:
- Internal method name (`getNodes`)
- Internal parameter name (`addressBookFilter`)
- Internal field name (`fileId`)
- Constraint type (`must not be null`)

While individually low-value, these details confirm internal class/parameter naming conventions and validation logic, aiding reconnaissance for further attacks. Severity: **Low–Medium** (CWE-209: Information Exposure Through an Error Message).

### Likelihood Explanation

Exploitability is trivial and requires zero privileges. Any gRPC client can send a well-formed `getNodes` request with an empty `AddressBookQuery` (no `fileId`). The behavior is deterministic and repeatable with no rate limiting or authentication required.

### Recommendation

1. **Sanitize the error message** in `ProtoUtil.toStatusRuntimeException()` for `ConstraintViolationException`: instead of `t.getMessage()`, return a generic string such as `"Invalid request parameters"`. [5](#0-4) 

2. **Alternatively, apply a default fileId** in `toFilter()` when `query.hasFileId()` is false (e.g., default to `addressBookFile102`), matching the documented behavior and eliminating the null path entirely. [6](#0-5) 

### Proof of Concept

```bash
# Using grpcurl (no authentication required)
grpcurl -plaintext \
  -proto addressbook.proto \
  -d '{}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.NetworkService/getNodes
```

**Expected response:**
```
ERROR:
  Code: InvalidArgument
  Message: getNodes.addressBookFilter.fileId: must not be null
```

The `Message` field in the gRPC error response contains the raw `ConstraintViolationException` message, disclosing internal implementation details to the unauthenticated caller.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L45-53)
```java
    private AddressBookFilter toFilter(final AddressBookQuery query) {
        final var filter = AddressBookFilter.builder().limit(query.getLimit());

        if (query.hasFileId()) {
            filter.fileId(EntityId.of(query.getFileId()));
        }

        return filter.build();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/AddressBookFilter.java (L13-16)
```java
public class AddressBookFilter {
    @NotNull
    private final EntityId fileId;

```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkService.java (L12-12)
```java
    Flux<AddressBookEntry> getNodes(@Valid AddressBookFilter addressBookFilter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L35-36)
```java
@Validated
public class NetworkServiceImpl implements NetworkService {
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/util/ProtoUtil.java (L47-50)
```java
        } else if (t instanceof ConstraintViolationException
                || t instanceof IllegalArgumentException
                || t instanceof InvalidEntityException) {
            return clientError(t, Status.INVALID_ARGUMENT, t.getMessage());
```
