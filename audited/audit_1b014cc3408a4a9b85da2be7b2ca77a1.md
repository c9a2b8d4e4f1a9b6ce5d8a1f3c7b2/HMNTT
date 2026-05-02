### Title
Missing Address Book File ID Validation in REST Java `getNetworkNodes` Allows Arbitrary fileId to Return Empty Node List

### Summary
The REST Java `NetworkServiceImpl.getNetworkNodes()` passes the caller-supplied `fileId` directly to the database query without validating it against the two known valid address book file IDs (101 and 102). An unprivileged external user can supply any arbitrary entity ID as `file.id`, causing the query to match no address book and return an empty node list. The sibling gRPC service has this validation; the REST Java service does not.

### Finding Description

**Code path:**

1. `NetworkController.java` lines 152–157: The controller only checks that the operator is `EQ`; it does not validate the numeric value of `fileId`. [1](#0-0) 

2. `NetworkServiceImpl.java` lines 178–182: `getAddressBookFileId()` returns the raw caller-supplied value with no allowlist check. [2](#0-1) 

3. `NetworkNodeRepository.java` lines 26–31: The SQL CTE filters `address_book` by `file_id = :fileId`. If the supplied ID does not exist in the table, the CTE is empty, the join produces zero rows, and the response is an empty node list. [3](#0-2) 

**Root cause:** The REST Java service omits the allowlist guard that the gRPC `NetworkServiceImpl` applies explicitly: [4](#0-3) 

The gRPC service maintains `validFileIds = {addressBookFile101, addressBookFile102}` and throws `IllegalArgumentException("Not a valid address book file")` for any other value. The REST Java service has no equivalent guard.

**Confirmed by existing test** — the test `notFoundWithInvalidFileId` explicitly sends `?file.id=0.0.99999` and asserts an empty `nodes` list is returned with HTTP 200, confirming the behavior is reachable and produces silent data suppression rather than an error: [5](#0-4) 

### Impact Explanation
Any client (SDK, wallet, monitoring tool) that calls `GET /api/v1/network/nodes?file.id=<arbitrary>` receives HTTP 200 with an empty `nodes` array. Because the response is well-formed and successful, clients that do not separately validate the result will silently treat the network as having zero nodes, preventing them from discovering consensus nodes and effectively partitioning them from the network. The silent 200-OK response (rather than a 400 error) makes this harder to detect than an explicit failure.

### Likelihood Explanation
No authentication or privilege is required. The parameter is a standard query string accepted by a public REST endpoint. The exploit is a single HTTP GET request. Any user who can reach the API can trigger it. The behavior is stable and repeatable.

### Recommendation
Apply the same allowlist guard used in the gRPC service. In `NetworkServiceImpl.getAddressBookFileId()` (or in the controller before calling the service), validate the supplied fileId against the two known valid values:

```java
private static final Set<Long> VALID_FILE_IDS = Set.of(
    systemEntity.addressBookFile101().getId(),
    systemEntity.addressBookFile102().getId()
);

private long getAddressBookFileId(final NetworkNodeRequest request) {
    if (request.getFileId() == null) {
        return systemEntity.addressBookFile102().getId();
    }
    long id = request.getFileId().value();
    if (!VALID_FILE_IDS.contains(id)) {
        throw new IllegalArgumentException("Not a valid address book file");
    }
    return id;
}
```

This mirrors the guard already present in `grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java` lines 50–59 and returns HTTP 400 instead of a silent empty result. [4](#0-3) 

### Proof of Concept

**Precondition:** The mirror node REST Java service is running and the `address_book` table contains entries only for file IDs 101 and 102.

**Step 1 — Baseline (valid request):**
```
GET /api/v1/network/nodes
→ HTTP 200, nodes: [ ...real node list... ]
```

**Step 2 — Exploit (arbitrary fileId):**
```
GET /api/v1/network/nodes?file.id=0.0.99999
→ HTTP 200, nodes: []
```

The response is indistinguishable from a legitimately empty network. A client consuming this response will believe no consensus nodes exist. The test at `NetworkControllerTest.java:1657–1669` reproduces this exactly. [5](#0-4)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L152-157)
```java
    @GetMapping("/nodes")
    ResponseEntity<NetworkNodesResponse> getNodes(@RequestParameter NetworkNodeRequest request) {
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L26-31)
```java
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
                order by start_consensus_timestamp desc
                limit 1
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

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/NetworkControllerTest.java (L1657-1669)
```java
        @Test
        void notFoundWithInvalidFileId() {
            // given
            setupNetworkNodeData();

            // when
            final var actual =
                    restClient.get().uri("?file.id=0.0.99999").retrieve().body(NetworkNodesResponse.class);

            // then - should return empty results
            assertThat(actual).isNotNull();
            assertThat(actual.getNodes()).isNotNull().isEmpty();
        }
```
