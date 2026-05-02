### Title
Unvalidated `fileId` Parameter Allows Silent Empty Node List Response

### Summary
The `getNetworkNodes` method in `NetworkServiceImpl` accepts a caller-supplied `fileId` and passes it directly to the SQL query without validating that it corresponds to a real address book entry. When the supplied `fileId` matches no row in the `address_book` table, the `latest_address_book` CTE returns zero rows, the inner JOIN produces an empty result set, and the API silently returns an empty node list — with no error or indication that the parameter was invalid.

### Finding Description
**Code path:**

In `NetworkServiceImpl.java` lines 178–182, `getAddressBookFileId` uses the caller-supplied value verbatim:

```java
private long getAddressBookFileId(final NetworkNodeRequest request) {
    return request.getFileId() != null
            ? request.getFileId().value()          // ← no existence check
            : systemEntity.addressBookFile102().getId();
}
``` [1](#0-0) 

This value is forwarded directly to `networkNodeRepository.findNetworkNodes(fileId, ...)` at line 135–136. [2](#0-1) 

Inside the native SQL query, the `latest_address_book` CTE filters on `file_id = :fileId`:

```sql
with latest_address_book as (
    select start_consensus_timestamp, end_consensus_timestamp, file_id
    from address_book
    where file_id = :fileId          -- ← attacker-controlled
    order by start_consensus_timestamp desc
    limit 1
),
``` [3](#0-2) 

The main query then does an **inner JOIN** against this CTE:

```sql
from address_book_entry abe
join latest_address_book ab
  on ab.start_consensus_timestamp = abe.consensus_timestamp
``` [4](#0-3) 

If the CTE is empty (no matching `file_id`), the inner JOIN eliminates all rows and the method returns an empty list. No exception is thrown, no error is surfaced to the caller.

**Root cause:** `EntityIdRangeParameter.valueOf()` performs only syntactic validation (correct shard/realm/num format); it does not verify that the entity ID corresponds to an existing address book file. [5](#0-4) 

The only valid address book file IDs are `0.0.101` and `0.0.102`. There is no allowlist or existence check anywhere in the call chain.

### Impact Explanation
Any caller who supplies `file.id=0.0.999` (or any other non-existent entity ID) receives a `200 OK` response with an empty `nodes` array. A client application relying on this endpoint to discover gossip endpoints will silently conclude there are no nodes to connect to, breaking transaction submission. Because the response is `200 OK` with an empty list (indistinguishable from a legitimately empty network), the client has no signal that the parameter was invalid. This can be used in social-engineering or supply-chain scenarios where a crafted URL is passed to a client library.

### Likelihood Explanation
The parameter is unauthenticated and requires no privileges — any HTTP client can trigger this. The exploit is a single query string parameter change (`?file.id=0.0.1`). It is trivially repeatable and requires no special knowledge beyond the public API documentation.

### Recommendation
Restrict the accepted `fileId` values to the known valid address book file IDs (`0.0.101` and `0.0.102`). In `getAddressBookFileId`, validate the supplied value against this allowlist and throw an `IllegalArgumentException` (resulting in a `400 Bad Request`) if it does not match:

```java
private static final Set<Long> VALID_ADDRESS_BOOK_FILE_IDS = Set.of(
    systemEntity.addressBookFile101().getId(),
    systemEntity.addressBookFile102().getId()
);

private long getAddressBookFileId(final NetworkNodeRequest request) {
    if (request.getFileId() == null) {
        return systemEntity.addressBookFile102().getId();
    }
    long id = request.getFileId().value();
    if (!VALID_ADDRESS_BOOK_FILE_IDS.contains(id)) {
        throw new IllegalArgumentException("Invalid file.id: must be 0.0.101 or 0.0.102");
    }
    return id;
}
```

### Proof of Concept
```
GET /api/v1/network/nodes?file.id=0.0.999
```
Expected (correct) response: `400 Bad Request`  
Actual response:
```json
{
  "nodes": [],
  "links": { "next": null }
}
```
Steps:
1. Start the mirror node REST-Java service with a populated database.
2. Confirm `GET /api/v1/network/nodes` returns a non-empty node list.
3. Issue `GET /api/v1/network/nodes?file.id=0.0.999`.
4. Observe `200 OK` with `"nodes": []` — all gossip endpoints hidden from the caller.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L135-136)
```java
        return networkNodeRepository.findNetworkNodes(
                fileId, nodeIdArray, lowerBound, upperBound, orderDirection, limit);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L178-182)
```java
    private long getAddressBookFileId(final NetworkNodeRequest request) {
        return request.getFileId() != null
                ? request.getFileId().value()
                : systemEntity.addressBookFile102().getId();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L26-33)
```java
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
                order by start_consensus_timestamp desc
                limit 1
            ),
            latest_node_stake as (
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L89-91)
```java
            from address_book_entry abe
            join latest_address_book ab
              on ab.start_consensus_timestamp = abe.consensus_timestamp
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdRangeParameter.java (L22-33)
```java
    public static EntityIdRangeParameter valueOf(String entityIdRangeParam) {
        if (StringUtils.isBlank(entityIdRangeParam)) {
            return EMPTY;
        }

        var splitVal = entityIdRangeParam.split(":");
        return switch (splitVal.length) {
            case 1 -> new EntityIdRangeParameter(RangeOperator.EQ, getEntityId(splitVal[0]));
            case 2 -> new EntityIdRangeParameter(RangeOperator.of(splitVal[0]), getEntityId(splitVal[1]));
            default -> throw new IllegalArgumentException("Invalid range operator. Should have format 'operator:ID'");
        };
    }
```
