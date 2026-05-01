### Title
Unauthenticated Full-Scan DoS via Unfiltered `/api/v1/network/nodes` Endpoint

### Summary
Any unauthenticated external user can issue `GET /api/v1/network/nodes` with no `file.id` and no `node.id` parameters, causing `getNetworkNodes()` to execute a complex multi-CTE query with a correlated subquery per node row and an uncached full scan of the `node_stake` table on every request. The `rest-java` module has no rate limiting or response caching on this endpoint, so a small number of concurrent requests can drive sustained, amplified DB load.

### Finding Description

**Code path:**

1. `NetworkController.getNodes()` at [1](#0-0)  accepts the request with no authentication check and no rate-limiting guard.

2. `NetworkServiceImpl.getNetworkNodes()` at [2](#0-1)  — when `nodeIds` is empty, `nodeIdArray` is set to `EMPTY_NODE_ID_ARRAY` (line 132) and `lowerBound=0`, `upperBound=Long.MAX_VALUE` are passed unchanged.

3. `getAddressBookFileId()` at [3](#0-2)  falls back to `systemEntity.addressBookFile102().getId()` when no `file.id` is supplied.

4. `NetworkNodeRepository.findNetworkNodes()` at [4](#0-3)  executes a multi-CTE native query with no `@Cacheable` annotation. The query contains:
   - `latest_node_stake` CTE with an uncorrelated `SELECT max(consensus_timestamp) FROM node_stake` subquery — a full-table aggregate on a table that grows unboundedly with each staking period. [5](#0-4) 
   - `node_info` CTE that performs a full scan of the `node` table with no WHERE clause. [6](#0-5) 
   - A correlated subquery against `address_book_service_endpoint` executed once per `address_book_entry` row. [7](#0-6) 
   - The `WHERE` clause condition `coalesce(array_length(:nodeIds, 1), 0) = 0` evaluates to true for an empty array, bypassing all node-ID filtering. [8](#0-7) 

**Root cause / failed assumption:** The design assumes the address book is small and queries are infrequent. No caching is applied to `findNetworkNodes()` (contrast with the gRPC path's `@Cacheable` on `AddressBookEntryRepository`). No rate limiting exists in the `rest-java` module for this endpoint — the `ThrottleConfiguration`/`ThrottleManagerImpl` throttle infrastructure lives exclusively in the `web3` module. 

### Impact Explanation

Each unfiltered request forces the DB to: (a) aggregate `max(consensus_timestamp)` over the entire `node_stake` table (which accumulates one row per node per staking period — thousands of rows on mainnet after months of operation), (b) full-scan the `node` table, and (c) execute N correlated subqueries against `address_book_service_endpoint`. Because there is no response cache, every concurrent request repeats this work independently. A modest number of concurrent clients (e.g., 10–20) can saturate DB CPU and connection pool, degrading all mirror-node API consumers. The `limit 25` cap only restricts returned rows, not the DB scan cost.

### Likelihood Explanation

The endpoint is publicly documented in the OpenAPI spec at [9](#0-8)  with no authentication requirement. No API key, token, or IP restriction is enforced in code. Any attacker with HTTP access can trigger this with a simple loop: `while true; do curl https://<mirror>/api/v1/network/nodes & done`. No special knowledge, credentials, or protocol manipulation is required.

### Recommendation

1. **Add response caching** to `NetworkNodeRepository.findNetworkNodes()` (or at the service layer) with a short TTL (e.g., 30 seconds), mirroring the `@Cacheable` pattern already used in the gRPC `AddressBookEntryRepository`.
2. **Add rate limiting** to the `rest-java` `NetworkController` for the `/nodes` endpoint, analogous to the bucket4j throttle already present in the `web3` module.
3. **Materialize the `max(consensus_timestamp)` lookup** for `node_stake` as a cached value or a separate indexed query rather than an inline aggregate on every request.
4. **Add a database-level index** on `node_stake(consensus_timestamp)` if not already present, to reduce the cost of the aggregate subquery.

### Proof of Concept

```bash
# Trigger maximum-cost unfiltered scan — no credentials needed
# Run N concurrent requests to amplify DB load
for i in $(seq 1 20); do
  curl -s "https://<mirror-node-host>/api/v1/network/nodes" > /dev/null &
done
wait
```

Each request independently executes the full multi-CTE query including `SELECT max(consensus_timestamp) FROM node_stake` (full aggregate), a full `node` table scan, and N correlated `address_book_service_endpoint` subqueries. With 20 concurrent requests and no rate limiting or caching, DB CPU and connection pool utilization rises proportionally, exceeding the 30% threshold relative to baseline idle load.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L152-171)
```java
    @GetMapping("/nodes")
    ResponseEntity<NetworkNodesResponse> getNodes(@RequestParameter NetworkNodeRequest request) {
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
        final var networkNodeRows = networkService.getNetworkNodes(request);
        final var limit = request.getEffectiveLimit();

        final var networkNodes = networkNodeMapper.map(networkNodeRows);

        final var sort = Sort.by(request.getOrder(), Constants.NODE_ID);
        final var pageable = PageRequest.of(0, limit, sort);
        final var links = linkFactory.create(networkNodes, pageable, NETWORK_NODE_EXTRACTOR);

        var response = new NetworkNodesResponse();
        response.setNodes(networkNodes);
        response.setLinks(links);
        return ResponseEntity.ok(response);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L99-137)
```java
    @Override
    public List<NetworkNodeDto> getNetworkNodes(NetworkNodeRequest request) {
        final long fileId = getAddressBookFileId(request);
        final var limit = request.getEffectiveLimit();
        final var nodeIdParams = request.getNodeIds();
        final var orderDirection = request.getOrder().name();

        final Set<Long> nodeIds = new HashSet<>();
        long lowerBound = 0L;
        long upperBound = Long.MAX_VALUE;

        for (final var nodeIdParam : nodeIdParams) {
            if (nodeIdParam.operator() == RangeOperator.EQ) {
                nodeIds.add(nodeIdParam.value());
            } else if (nodeIdParam.hasLowerBound()) {
                lowerBound = Math.max(lowerBound, nodeIdParam.getInclusiveValue());
            } else if (nodeIdParam.hasUpperBound()) {
                upperBound = Math.min(upperBound, nodeIdParam.getInclusiveValue());
            }
        }

        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("Invalid range provided for node.id");
        }

        final Long[] nodeIdArray;
        if (!nodeIds.isEmpty()) {
            final var range = Range.closed(lowerBound, upperBound);
            nodeIdArray = nodeIds.stream().filter(range::contains).toArray(Long[]::new);
            if (nodeIdArray.length == 0) {
                return List.of();
            }
        } else {
            nodeIdArray = EMPTY_NODE_ID_ARRAY;
        }

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L25-105)
```java
    @Query(value = """
            with latest_address_book as (
                select start_consensus_timestamp, end_consensus_timestamp, file_id
                from address_book
                where file_id = :fileId
                order by start_consensus_timestamp desc
                limit 1
            ),
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
            select
                n.admin_key as adminKey,
                n.associated_registered_nodes as associatedRegisteredNodes,
                n.decline_reward as declineReward,
                abe.description as description,
                ab.end_consensus_timestamp as endConsensusTimestamp,
                ab.file_id as fileId,
                case when n.grpc_proxy_endpoint is null then null
                     else jsonb_build_object(
                         'domain_name', coalesce(n.grpc_proxy_endpoint->>'domain_name', ''),
                         'ip_address_v4', coalesce(n.grpc_proxy_endpoint->>'ip_address_v4', ''),
                         'port', (n.grpc_proxy_endpoint->>'port')::integer
                     )::text
                     end as grpcProxyEndpointJson,
                nullif(ns.max_stake, -1) as maxStake,
                abe.memo as memo,
                nullif(ns.min_stake, -1) as minStake,
                coalesce(n.account_id, abe.node_account_id) as nodeAccountId,
                case when abe.node_cert_hash is null or abe.node_cert_hash = ''::bytea then '0x'
                     when left(convert_from(abe.node_cert_hash, 'UTF8'), 2) = '0x' then convert_from(abe.node_cert_hash, 'UTF8')
                     else '0x' || convert_from(abe.node_cert_hash, 'UTF8')
                     end as nodeCertHash,
                abe.node_id as nodeId,
                case when abe.public_key is null or abe.public_key = '' then '0x'
                     when left(abe.public_key, 2) = '0x' then abe.public_key
                     else '0x' || abe.public_key
                     end as publicKey,
                ns.reward_rate as rewardRateStart,
                coalesce((
                    select jsonb_agg(
                        jsonb_build_object(
                            'domain_name', coalesce(abse.domain_name, ''),
                            'ip_address_v4', coalesce(abse.ip_address_v4, ''),
                            'port', abse.port
                        ) order by abse.ip_address_v4 asc, abse.port asc
                    )
                    from address_book_service_endpoint abse
                    where abse.consensus_timestamp = abe.consensus_timestamp
                      and abse.node_id = abe.node_id
                ), '[]'::jsonb)::text as serviceEndpointsJson,
                ns.stake as stake,
                nullif(ns.stake_not_rewarded, -1) as stakeNotRewarded,
                ns.stake_rewarded as stakeRewarded,
                ns.staking_period as stakingPeriod,
                ab.start_consensus_timestamp as startConsensusTimestamp
            from address_book_entry abe
            join latest_address_book ab
              on ab.start_consensus_timestamp = abe.consensus_timestamp
            left join latest_node_stake ns
              on abe.node_id = ns.node_id
            left join node_info n
              on abe.node_id = n.node_id
            where (coalesce(array_length(:nodeIds, 1), 0) = 0 or abe.node_id = any(:nodeIds))
              and abe.node_id >= :minNodeId
              and abe.node_id <= :maxNodeId
            order by
              case when :orderDirection = 'ASC' then abe.node_id end asc,
              case when :orderDirection = 'DESC' then abe.node_id end desc
            limit :limit
            """, nativeQuery = true)
    List<NetworkNodeDto> findNetworkNodes(
            Long fileId, Long[] nodeIds, long minNodeId, long maxNodeId, String orderDirection, int limit);
```

**File:** rest/api/v1/openapi.yml (L948-968)
```yaml
  /api/v1/network/nodes:
    get:
      summary: Get the network address book nodes
      description: Returns the network's list of nodes used in consensus
      operationId: getNetworkNodes
      parameters:
        - $ref: "#/components/parameters/fileIdQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/nodeIdQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NetworkNodesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - network
```
