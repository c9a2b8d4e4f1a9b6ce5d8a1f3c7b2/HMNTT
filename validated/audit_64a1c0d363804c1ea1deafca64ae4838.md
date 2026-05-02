All code references in the claim were verified against the actual repository. Here is the result:

---

Audit Report

## Title
Missing File ID Whitelist Validation in REST `/api/v1/network/nodes` Allows Arbitrary File ID Injection Returning Empty Node List

## Summary
The REST Java `getNodes()` endpoint in `NetworkController` validates only that the `file.id` parameter uses the equality operator, but never validates that the supplied value is one of the two legitimate address book file IDs (`0.0.101` or `0.0.102`). An unauthenticated caller can supply any non-existent file ID (e.g., `file.id=eq:0`), causing the SQL CTE to find no matching address book row and return an empty node list. The gRPC path enforces an explicit whitelist for the same data; the REST path does not.

## Finding Description

**Step 1 — Operator-only check in `NetworkController.java`:**

The controller validates only the operator, not the value: [1](#0-0) 

Any numeric entity ID — including `0` — passes this check.

**Step 2 — `getAddressBookFileId()` blindly forwards the caller-supplied value:** [2](#0-1) 

No whitelist check is performed; the raw `fileId` is returned directly.

**Step 3 — SQL CTE filters `address_book` by the raw `fileId`:** [3](#0-2) 

When no row exists for the supplied file ID, the CTE is empty, the join produces zero rows, and the response is `{"nodes": [], "links": {}}`.

**Step 4 — Parser accepts `0`:**

`EntityIdRangeParameter.valueOf("eq:0")` succeeds because the `filter(n -> n >= 0)` predicate accepts `0`: [4](#0-3) 

**Step 5 — Contrast with the gRPC path, which enforces a whitelist:** [5](#0-4) 

The REST path has no equivalent guard.

## Impact Explanation
Any unauthenticated client can force the endpoint to return an empty node list by supplying a non-existent file ID. SDKs or monitoring tools that call `GET /api/v1/network/nodes` to bootstrap their peer list will receive zero nodes and may halt all transaction submission, treating the result as a complete network partition. The impact is application-layer denial of service for any consumer that trusts this endpoint without independent verification.

## Likelihood Explanation
No authentication or special privilege is required. The `file.id` parameter is a standard documented query parameter. The attack is a single HTTP GET request, trivially repeatable, and requires no prior knowledge beyond the public API documentation.

## Recommendation
Add a whitelist check in `NetworkServiceImpl.getAddressBookFileId()` (or in `NetworkController.getNodes()`) mirroring the gRPC path:

```java
private long getAddressBookFileId(final NetworkNodeRequest request) {
    if (request.getFileId() == null) {
        return systemEntity.addressBookFile102().getId();
    }
    long id = request.getFileId().value();
    long file101 = systemEntity.addressBookFile101().getId();
    long file102 = systemEntity.addressBookFile102().getId();
    if (id != file101 && id != file102) {
        throw new IllegalArgumentException("Not a valid address book file");
    }
    return id;
}
```

This aligns the REST path with the existing gRPC whitelist at [6](#0-5) .

## Proof of Concept
```
GET /api/v1/network/nodes?file.id=eq:0
```
Response:
```json
{"nodes": [], "links": {}}
```
No authentication required. Any numeric entity ID that does not correspond to an existing address book row produces the same result.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L154-157)
```java
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L178-182)
```java
    private long getAddressBookFileId(final NetworkNodeRequest request) {
        return request.getFileId() != null
                ? request.getFileId().value()
                : systemEntity.addressBookFile102().getId();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L26-30)
```java
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
                order by start_consensus_timestamp desc
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdRangeParameter.java (L36-40)
```java
        List<Long> parts = Splitter.on('.')
                .splitToStream(Objects.requireNonNullElse(entityId, ""))
                .map(Long::valueOf)
                .filter(n -> n >= 0)
                .toList();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L50-59)
```java
    @Getter(lazy = true, value = AccessLevel.PRIVATE)
    private final Set<EntityId> validFileIds =
            Set.of(systemEntity.addressBookFile101(), systemEntity.addressBookFile102());

    @Override
    public Flux<AddressBookEntry> getNodes(AddressBookFilter filter) {
        var fileId = filter.getFileId();
        if (!getValidFileIds().contains(fileId)) {
            throw new IllegalArgumentException(INVALID_FILE_ID);
        }
```
