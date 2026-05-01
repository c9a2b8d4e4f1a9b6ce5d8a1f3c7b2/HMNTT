### Title
Missing fileId Whitelist Validation in `getNetworkNodes()` Enables Arbitrary DB Query Amplification

### Summary
The REST Java `NetworkServiceImpl.getNetworkNodes()` method accepts any arbitrary `file.id` value from unauthenticated callers and passes it directly to a complex multi-CTE SQL query without validating it against the known valid address book file IDs (101/102). Unlike the gRPC counterpart which enforces a strict whitelist, the REST Java service has no such guard, and no rate limiting exists on this endpoint within the `rest-java` module. An attacker can flood the endpoint with arbitrary fileId values, forcing repeated execution of an expensive SQL query including a full `max(consensus_timestamp)` aggregation on the `node_stake` table.

### Finding Description
**Code path:**

`NetworkController.getNodes()` (line 155) only validates that the `file.id` operator is `EQ`, not that the value is a valid address book file ID: [1](#0-0) 

`NetworkServiceImpl.getAddressBookFileId()` (lines 178–182) blindly returns whatever value the caller supplied: [2](#0-1) 

This arbitrary value is forwarded directly to `networkNodeRepository.findNetworkNodes()`: [3](#0-2) 

The SQL query executed contains a `latest_node_stake` CTE that always runs `select max(consensus_timestamp) from node_stake` regardless of whether the supplied `fileId` matches any real address book: [4](#0-3) 

**Contrast with the gRPC service**, which enforces a strict whitelist before any DB access: [5](#0-4) 

The valid set is `{addressBookFile101, addressBookFile102}`. The REST Java service has no equivalent check.

**Why existing checks fail:**
- The controller's operator check (`fileId.operator() != RangeOperator.EQ`) only rejects non-equality operators; it does not restrict the value space.
- The `rest-java` module has no rate-limiting filter (the `ThrottleConfiguration`/`ThrottleManagerImpl` found in the codebase belongs exclusively to the `web3` module for contract calls).
- The `MetricsFilter` in `rest-java` only records metrics; it does not throttle. [6](#0-5) 

### Impact Explanation
Every request with an arbitrary `file.id` causes the database to execute the full multi-CTE query. The `latest_node_stake` CTE performs `select max(consensus_timestamp) from node_stake`, which is a full-table aggregation if `consensus_timestamp` is not indexed as a standalone column. Even when `latest_address_book` returns zero rows (because the fileId is bogus), PostgreSQL evaluates the CTE definitions before the join short-circuits. At high request volume this degrades DB performance for all legitimate users of the mirror node, consistent with the "griefing / no economic damage" severity classification.

### Likelihood Explanation
The endpoint is unauthenticated, publicly reachable, and requires only a single HTTP GET with a numeric query parameter. No API key, token, or privileged access is needed. The attack is trivially scriptable (`curl` loop or any HTTP load tool) and can be sustained indefinitely. Because each request uses a different fileId value, response caching (if any) provides no protection.

### Recommendation
Add a whitelist check in `NetworkServiceImpl.getAddressBookFileId()` mirroring the gRPC service:

```java
private static final Set<Long> VALID_FILE_IDS = Set.of(
    systemEntity.addressBookFile101().getId(),
    systemEntity.addressBookFile102().getId()
);

private long getAddressBookFileId(final NetworkNodeRequest request) {
    long fileId = request.getFileId() != null
        ? request.getFileId().value()
        : systemEntity.addressBookFile102().getId();
    if (!VALID_FILE_IDS.contains(fileId)) {
        throw new IllegalArgumentException("Not a valid address book file");
    }
    return fileId;
}
```

Additionally, apply a per-IP or global rate limit to the `/api/v1/network/nodes` endpoint within the `rest-java` module.

### Proof of Concept
```bash
# Flood with arbitrary fileId values — no authentication required
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node-host>/api/v1/network/nodes?file.id=$((RANDOM + 200))" &
done
wait
```

Each request causes the database to execute the full CTE query including `select max(consensus_timestamp) from node_stake`. Monitor DB CPU/query latency to observe degradation for concurrent legitimate requests.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L154-158)
```java
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
        final var networkNodeRows = networkService.getNetworkNodes(request);
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L33-43)
```java
            latest_node_stake as (
                select max_stake, min_stake, node_id, reward_rate,
                       stake, stake_not_rewarded, stake_rewarded,
                       staking_period
                from node_stake
                where consensus_timestamp = (select max(consensus_timestamp) from node_stake)
            ),
            node_info as (
                select account_id, admin_key, associated_registered_nodes, decline_reward, grpc_proxy_endpoint, node_id
                from node
            )
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L50-58)
```java
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            recordMetrics(request, response);
        }
    }
```
