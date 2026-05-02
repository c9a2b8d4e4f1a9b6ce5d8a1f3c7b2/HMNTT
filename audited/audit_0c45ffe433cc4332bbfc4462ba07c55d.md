### Title
Missing File ID Whitelist Validation in REST Java Network Nodes Endpoint Allows Empty Node List Response

### Summary
The `getNetworkNodes()` method in `NetworkServiceImpl` delegates file ID resolution to `getAddressBookFileId()`, which only checks for null but never validates the supplied value against the set of valid address book file IDs (101 and 102). An unprivileged user can supply any arbitrary entity ID (e.g., `0`) as `file.id`, causing the SQL query to match no rows in the `address_book` table and return an empty node list. Clients consuming this response would believe no network nodes exist, preventing transaction submission.

### Finding Description

**Code path:**

1. `NetworkController.getNodes()` ( [1](#0-0) ) only validates that the operator is `EQ`; it never validates the actual file ID value.

2. `EntityIdRangeParameter.getEntityId()` ( [2](#0-1) ) uses `.filter(n -> n >= 0)` — this rejects negative numbers but explicitly **allows `0`**. The subsequent size-equality check only catches negatives (which are filtered out, reducing `parts.size()`), so `file.id=0` passes cleanly and produces `EntityIdRangeParameter(EQ, 0)`.

3. `getAddressBookFileId()` ( [3](#0-2) ) only checks `request.getFileId() != null`. Since the parameter is present (not null), it returns `request.getFileId().value()` — which is `0` — with no whitelist check.

4. `findNetworkNodes(0, ...)` is called. The SQL CTE `latest_address_book` filters `where file_id = :fileId` ( [4](#0-3) ). No row in `address_book` has `file_id = 0`, so the CTE is empty, the JOIN to `address_book_entry` produces zero rows, and an empty list is returned.

**Root cause:** The REST Java service lacks the whitelist guard that the gRPC service correctly implements: [5](#0-4) 

### Impact Explanation
Any client calling `GET /api/v1/network/nodes?file.id=0` receives a valid HTTP 200 response with an empty `nodes` array. SDKs and wallets that rely on this endpoint to discover network nodes for transaction submission would interpret this as "no nodes available," effectively blocking all transaction submission for any client that caches or trusts this response. The impact is a targeted, on-demand denial of service against the network node discovery mechanism, without requiring any authentication or elevated privilege.

### Likelihood Explanation
This requires zero privileges — it is a plain unauthenticated GET request with a single crafted query parameter. The endpoint is public-facing by design. The attack is trivially repeatable, scriptable, and requires no special knowledge beyond reading the API documentation. Any external party can trigger it at will.

### Recommendation
Add a whitelist validation in `getAddressBookFileId()` (or in `NetworkController.getNodes()`) mirroring the gRPC service's guard:

```java
private long getAddressBookFileId(final NetworkNodeRequest request) {
    if (request.getFileId() == null) {
        return systemEntity.addressBookFile102().getId();
    }
    long id = request.getFileId().value();
    var valid = Set.of(
        systemEntity.addressBookFile101().getId(),
        systemEntity.addressBookFile102().getId()
    );
    if (!valid.contains(id)) {
        throw new IllegalArgumentException("Not a valid address book file");
    }
    return id;
}
```

This matches the existing pattern in [6](#0-5) .

### Proof of Concept

**Preconditions:** Mirror node REST Java service is running with a populated `address_book` table (file IDs 101/102 present).

**Steps:**

```
# Normal request — returns real nodes
GET /api/v1/network/nodes
→ HTTP 200, nodes: [{nodeId: 0, ...}, {nodeId: 1, ...}, ...]

# Attack request — supply invalid file ID 0
GET /api/v1/network/nodes?file.id=0
→ HTTP 200, nodes: []

# Also works with any other non-existent file ID
GET /api/v1/network/nodes?file.id=999
→ HTTP 200, nodes: []
```

**Result:** The attacker receives a legitimate 200 OK with an empty node list. Any client that uses this response to populate its node address book will find no nodes and be unable to submit transactions to the network.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L154-157)
```java
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdRangeParameter.java (L35-52)
```java
    private static EntityId getEntityId(String entityId) {
        List<Long> parts = Splitter.on('.')
                .splitToStream(Objects.requireNonNullElse(entityId, ""))
                .map(Long::valueOf)
                .filter(n -> n >= 0)
                .toList();

        if (parts.size() != StringUtils.countMatches(entityId, ".") + 1) {
            throw new IllegalArgumentException("Invalid entity ID");
        }

        var properties = CommonProperties.getInstance();
        return switch (parts.size()) {
            case 1 -> EntityId.of(properties.getShard(), properties.getRealm(), parts.get(0));
            case 2 -> EntityId.of(properties.getShard(), parts.get(0), parts.get(1));
            case 3 -> EntityId.of(parts.get(0), parts.get(1), parts.get(2));
            default -> throw new IllegalArgumentException("Invalid entity ID");
        };
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L178-182)
```java
    private long getAddressBookFileId(final NetworkNodeRequest request) {
        return request.getFileId() != null
                ? request.getFileId().value()
                : systemEntity.addressBookFile102().getId();
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
