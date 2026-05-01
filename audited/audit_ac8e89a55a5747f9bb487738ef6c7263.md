### Title
Silent Empty Node List via Arbitrary `file.id` Parameter in `getNetworkNodes`

### Summary
An unauthenticated external user can supply any arbitrary `file.id` query parameter to `GET /api/v1/network/nodes`. Because no validation checks whether the provided file ID corresponds to an existing address book, the SQL CTE silently returns zero rows, causing the endpoint to return an empty node list with HTTP 200. Clients relying on this endpoint for node discovery will believe no network nodes exist, preventing transaction submission.

### Finding Description

**Code path:**

1. **Controller** — `NetworkController.java` lines 154–157: The only check on `fileId` is that the operator must be `EQ`. No existence validation is performed. [1](#0-0) 

2. **Service** — `NetworkServiceImpl.java` lines 178–182: `getAddressBookFileId` blindly returns the caller-supplied value with no lookup against the database. [2](#0-1) 

3. **Repository SQL** — `NetworkNodeRepository.java` lines 26–29: The `latest_address_book` CTE filters `where file_id = :fileId`. If no address book row exists for the supplied ID, the CTE returns zero rows. [3](#0-2) 

4. **INNER JOIN** — line 91: `join latest_address_book ab on ab.start_consensus_timestamp = abe.consensus_timestamp` — because the CTE is empty, the join eliminates all `address_book_entry` rows, and `findNetworkNodes` returns an empty `List`. [4](#0-3) 

5. **No empty-result guard** — `getNetworkNodes` returns the empty list directly to the controller, which wraps it in a 200 OK response with `"nodes": []`. [5](#0-4) 

**Root cause:** The service assumes any caller-supplied `fileId` is valid and passes it directly to the repository. The SQL query has no fallback and no error path for a non-existent file ID; it simply returns empty.

### Impact Explanation
Any SDK, wallet, or relay that calls `/api/v1/network/nodes?file.id=<bogus>` to discover gossip/gRPC endpoints will receive an empty node list with a 200 OK. The client has no way to distinguish "no nodes exist" from "wrong file ID was queried." This can be used to silently misdirect node-discovery logic, causing transaction submission failures for any client that trusts the response without a secondary check. Severity is **medium-high** for availability: the mirror node itself is not compromised, but dependent clients are denied accurate topology data.

### Likelihood Explanation
The endpoint is public and unauthenticated. No special knowledge or privilege is required — only awareness of the `file.id` query parameter (documented in the API). The attack is trivially repeatable and requires a single HTTP GET request. Any automated client that caches the result of this call is persistently affected until it re-queries with the correct file ID.

### Recommendation
1. **Validate existence before use**: In `getAddressBookFileId` (or immediately after), verify that the supplied `fileId` corresponds to a known address book file (e.g., 101 or 102 for mainnet). Reject unknown values with a 400 Bad Request.
2. **Guard empty results**: After `findNetworkNodes` returns, if the list is empty and a non-default `fileId` was supplied, throw an `EntityNotFoundException` (HTTP 404) rather than returning an empty 200.
3. **Allowlist valid file IDs**: Since address book file IDs are well-known system entities (101, 102), restrict the `file.id` parameter to that allowlist at the controller layer.

### Proof of Concept
```
# Step 1: Query with a non-existent file ID
GET /api/v1/network/nodes?file.id=99999999

# Step 2: Observe HTTP 200 with empty node list
HTTP/1.1 200 OK
{
  "nodes": [],
  "links": { "next": null }
}

# Step 3: Compare with the legitimate default query
GET /api/v1/network/nodes

# Returns all nodes normally — confirming the empty result above
# is caused by the bogus file.id, not a real absence of nodes.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L154-157)
```java
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L135-137)
```java
        return networkNodeRepository.findNetworkNodes(
                fileId, nodeIdArray, lowerBound, upperBound, orderDirection, limit);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L26-29)
```java
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L89-92)
```java
            from address_book_entry abe
            join latest_address_book ab
              on ab.start_consensus_timestamp = abe.consensus_timestamp
            left join latest_node_stake ns
```
