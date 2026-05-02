### Title
Missing FileId Whitelist Validation in REST `getNetworkNodes` Allows Arbitrary Address Book Selection

### Summary
The REST Java `NetworkServiceImpl.getNetworkNodes` accepts any user-supplied `fileId` value without validating it against the permitted set of address book files (101 and 102). An unprivileged external user can supply `?file.id=101` to force the endpoint to return the stale bootstrap address book, or supply any arbitrary numeric fileId (e.g., `?file.id=999`) to receive an empty node list. Either outcome can prevent clients from correctly discovering live gossip endpoints for transaction routing.

### Finding Description

**Code path:**

`NetworkController.java` lines 154–157 perform the only controller-level check on `fileId`:

```java
if (fileId != null && fileId.operator() != RangeOperator.EQ) {
    throw new IllegalArgumentException("Only equality operator is supported for file.id");
}
```

This validates only the *operator type*, never the *value*. The request is then forwarded to `NetworkServiceImpl.getNetworkNodes`, which calls:

```java
private long getAddressBookFileId(final NetworkNodeRequest request) {
    return request.getFileId() != null
            ? request.getFileId().value()          // ← raw user value, no whitelist
            : systemEntity.addressBookFile102().getId();
}
```

The raw user-supplied long is passed directly to `NetworkNodeRepository.findNetworkNodes` as the `:fileId` bind parameter in the native SQL query `where file_id = :fileId`.

**Root cause:** The REST `NetworkServiceImpl` (rest-java module) has no whitelist check. By contrast, the gRPC `NetworkServiceImpl` (grpc module) explicitly maintains and enforces a whitelist:

```java
private final Set<EntityId> validFileIds =
        Set.of(systemEntity.addressBookFile101(), systemEntity.addressBookFile102());

if (!getValidFileIds().contains(fileId)) {
    throw new IllegalArgumentException(INVALID_FILE_ID);
}
```

This check is entirely absent from the REST path.

**Exploit flow:**

1. Attacker sends `GET /api/v1/network/nodes?file.id=101` — the controller passes the EQ operator check, `getAddressBookFileId` returns the encoded ID of file 101, and the SQL CTE `latest_address_book` selects the most recent address book row for file 101 (the bootstrap/genesis book). Clients receive the bootstrap node list, which may contain outdated IPs/ports for nodes that have since changed endpoints.

2. Alternatively, attacker sends `GET /api/v1/network/nodes?file.id=999` — the CTE finds no matching `address_book` row, the join produces zero rows, and the endpoint returns an empty node list with HTTP 200. Clients that rely on this endpoint for node discovery receive no usable gossip targets.

### Impact Explanation

File 101 is the bootstrap address book populated at genesis. In a live network it is typically superseded by file 102 updates and may contain stale service endpoints. Clients that consume the REST `/api/v1/network/nodes` endpoint to build their gossip peer list and receive file-101 data may attempt to connect to endpoints that no longer serve the network, causing submitted transactions to fail routing. Supplying a non-existent fileId produces an empty 200 response, which is indistinguishable from a legitimate "no nodes" result and silently breaks any client that treats an empty list as authoritative.

### Likelihood Explanation

No authentication or privilege is required. The parameter is a standard query string field documented in the OpenAPI spec (`fileIdQueryParam`). Any HTTP client can reproduce the request in a single unauthenticated GET. The attack is trivially repeatable and requires no special knowledge beyond reading the public API documentation.

### Recommendation

Add a whitelist check in `NetworkServiceImpl.getNetworkNodes` (rest-java) mirroring the gRPC implementation:

```java
private static final Set<Long> VALID_FILE_IDS = Set.of(
    systemEntity.addressBookFile101().getId(),
    systemEntity.addressBookFile102().getId()
);

private long getAddressBookFileId(final NetworkNodeRequest request) {
    long id = request.getFileId() != null
            ? request.getFileId().value()
            : systemEntity.addressBookFile102().getId();
    if (!VALID_FILE_IDS.contains(id)) {
        throw new IllegalArgumentException("Not a valid address book file");
    }
    return id;
}
```

### Proof of Concept

```bash
# Step 1 – retrieve bootstrap (file 101) address book instead of current (file 102)
curl -s "http://<mirror-node-host>/api/v1/network/nodes?file.id=101"
# Returns HTTP 200 with nodes from the genesis address book (potentially stale endpoints)

# Step 2 – force empty node list with a non-existent fileId
curl -s "http://<mirror-node-host>/api/v1/network/nodes?file.id=999"
# Returns HTTP 200 with {"nodes":[],"links":{}} — clients see no gossip peers
```

Both requests require no credentials and succeed against an unpatched deployment. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L178-182)
```java
    private long getAddressBookFileId(final NetworkNodeRequest request) {
        return request.getFileId() != null
                ? request.getFileId().value()
                : systemEntity.addressBookFile102().getId();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L152-158)
```java
    @GetMapping("/nodes")
    ResponseEntity<NetworkNodesResponse> getNodes(@RequestParameter NetworkNodeRequest request) {
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
        final var networkNodeRows = networkService.getNetworkNodes(request);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L25-32)
```java
    @Query(value = """
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
                order by start_consensus_timestamp desc
                limit 1
            ),
```
