### Title
Missing `fileId` Whitelist Validation in REST Java `getNetworkNodes()` Causes Silent Empty Node List

### Summary
The REST Java `NetworkServiceImpl.getNetworkNodes()` accepts an arbitrary user-supplied `file.id` query parameter and passes it directly to the SQL query without validating it against the known valid address book file IDs (101 and 102). When a non-existent `fileId` is supplied, the `latest_address_book` CTE returns no rows, the inner join produces an empty result set, and the API silently returns an empty node list — with no error — causing clients to believe no consensus nodes exist.

### Finding Description

**Controller** (`rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 154–157): The only validation on `file.id` is that the operator must be `EQ`. No check is made that the value is a valid address book file ID.

```java
if (fileId != null && fileId.operator() != RangeOperator.EQ) {
    throw new IllegalArgumentException("Only equality operator is supported for file.id");
}
```

**Service** (`rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java`, lines 178–182): `getAddressBookFileId()` blindly returns the user-supplied value with no whitelist check:

```java
private long getAddressBookFileId(final NetworkNodeRequest request) {
    return request.getFileId() != null
            ? request.getFileId().value()
            : systemEntity.addressBookFile102().getId();
}
```

**Repository SQL** (`rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java`, lines 26–91): The CTE filters by the user-controlled `fileId`:

```sql
with latest_address_book as (
    select start_consensus_timestamp, end_consensus_timestamp, file_id
    from address_book
    where file_id = :fileId          -- user-controlled, unvalidated
    order by start_consensus_timestamp desc
    limit 1
),
...
from address_book_entry abe
join latest_address_book ab          -- INNER JOIN: empty CTE = empty result
  on ab.start_consensus_timestamp = abe.consensus_timestamp
```

If `fileId` does not exist in `address_book`, the CTE returns zero rows. The `INNER JOIN` on `latest_address_book` then produces zero rows. The API returns `{"nodes": [], "links": {...}}` — no error, no 404, just an empty list.

**Contrast with the gRPC service** (`grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java`, lines 51–58): The gRPC path explicitly whitelists valid file IDs and throws `IllegalArgumentException` for anything else:

```java
private final Set<EntityId> validFileIds =
        Set.of(systemEntity.addressBookFile101(), systemEntity.addressBookFile102());

if (!getValidFileIds().contains(fileId)) {
    throw new IllegalArgumentException(INVALID_FILE_ID);
}
```

The REST Java service has no equivalent guard.

### Impact Explanation
Any unauthenticated HTTP client can query `GET /api/v1/network/nodes?file.id=0.0.999999` and receive a well-formed, HTTP 200 response with an empty node list. SDK clients or custom integrations that use this endpoint for node discovery and trust the response will conclude that no consensus nodes exist and halt or fail transaction submission. This is a denial-of-service against the node-discovery mechanism, achievable with a single crafted request, with no authentication required.

### Likelihood Explanation
The exploit requires zero privileges, zero authentication, and a single HTTP GET request with a crafted `file.id` parameter. The parameter is documented and publicly accessible. Any attacker who reads the API docs or observes normal traffic can reproduce this trivially and repeatedly. The attack is stateless and leaves no persistent side effects, making it easy to automate.

### Recommendation
Add a whitelist check in `NetworkServiceImpl.getAddressBookFileId()` (or at the controller layer) mirroring the gRPC service:

```java
private static final Set<Long> VALID_FILE_IDS = Set.of(101L, 102L); // or use systemEntity

private long getAddressBookFileId(final NetworkNodeRequest request) {
    if (request.getFileId() == null) {
        return systemEntity.addressBookFile102().getId();
    }
    long id = request.getFileId().value();
    if (!Set.of(systemEntity.addressBookFile101().getId(),
                systemEntity.addressBookFile102().getId()).contains(id)) {
        throw new IllegalArgumentException("Not a valid address book file");
    }
    return id;
}
```

Alternatively, the SQL query could be changed to throw or return an error when the CTE is empty, but the whitelist approach is simpler and consistent with the existing gRPC implementation.

### Proof of Concept

**Precondition:** Mirror node REST Java service is running with a populated `address_book` table for file IDs 101 and 102.

**Step 1 — Confirm normal behavior:**
```
GET /api/v1/network/nodes
→ HTTP 200, {"nodes": [...3+ nodes...], "links": {...}}
```

**Step 2 — Trigger the vulnerability with a non-existent fileId:**
```
GET /api/v1/network/nodes?file.id=0.0.999999
→ HTTP 200, {"nodes": [], "links": {"next": null}}
```

**Step 3 — Observe:** The response is indistinguishable from a legitimate "no nodes found" response. A client that iterates this list to build its node roster will have an empty roster and cannot submit transactions.

**Relevant code locations:**
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 
- [4](#0-3) 
- [5](#0-4)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L178-182)
```java
    private long getAddressBookFileId(final NetworkNodeRequest request) {
        return request.getFileId() != null
                ? request.getFileId().value()
                : systemEntity.addressBookFile102().getId();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L154-157)
```java
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L26-32)
```java
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
                order by start_consensus_timestamp desc
                limit 1
            ),
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L89-92)
```java
            from address_book_entry abe
            join latest_address_book ab
              on ab.start_consensus_timestamp = abe.consensus_timestamp
            left join latest_node_stake ns
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
