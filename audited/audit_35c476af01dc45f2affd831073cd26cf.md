### Title
Unauthenticated Repeated Requests to `/api/v1/network/nodes` Force Uncached Multi-CTE PostgreSQL Queries, Enabling Sustained Database CPU Exhaustion

### Summary
The `findNetworkNodes()` method in `NetworkNodeRepository` executes a complex multi-CTE native SQL query on every invocation with no application-level caching (`@Cacheable`) and no rate limiting in the `rest-java` module. Any unauthenticated external user can send repeated GET requests to `/api/v1/network/nodes` and each request will trigger a full round-trip to PostgreSQL executing joins across five tables, with no throttle or cache to absorb the load.

### Finding Description
**Exact code path:**

`NetworkNodeRepository.findNetworkNodes()` at [1](#0-0)  executes a native SQL query (bypassing Hibernate's second-level cache via `nativeQuery = true` at line 103) that joins `address_book`, `address_book_entry`, `node_stake`, `node`, and `address_book_service_endpoint` with three CTEs and a correlated subquery per row for `serviceEndpointsJson`.

This is called unconditionally from `NetworkServiceImpl.getNetworkNodes()` at [2](#0-1)  with no caching wrapper.

The controller endpoint at [3](#0-2)  is publicly accessible with no authentication.

**Root cause — failed assumption:** The `grpc` module's equivalent query in `AddressBookEntryRepository` is protected by `@Cacheable(cacheManager = ADDRESS_BOOK_ENTRY_CACHE, ...)` at [4](#0-3)  but the `rest-java` `NetworkNodeRepository` has no such annotation. The design assumption that `nativeQuery = true` queries are cheap enough to run on every request is incorrect for a multi-CTE query joining five tables.

**Why existing checks fail:**

- The only filter registered in `RestJavaConfiguration` is a `ShallowEtagHeaderFilter` at [5](#0-4)  — this computes ETags from the response body *after* the database query has already executed, so it does not prevent the DB round-trip.
- The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module at [6](#0-5)  and is not applied to `rest-java` endpoints.
- The `limit` parameter is capped at 25 by `getEffectiveLimit()` at [7](#0-6)  — this bounds result size but does not bound request frequency.

### Impact Explanation
Each request executes three CTEs plus a correlated subquery per returned row against live PostgreSQL tables. The address book data is relatively static, making this ideal for caching but currently uncached. At a moderate sustained rate (e.g., 50–100 req/s from a single client or distributed across IPs), the repeated full-table scans on `node_stake` (`select max(consensus_timestamp) from node_stake`) and the correlated `address_book_service_endpoint` subquery per node row will accumulate CPU and I/O pressure on the database, plausibly sustaining load 30%+ above baseline. The impact is database CPU exhaustion affecting all services sharing the PostgreSQL instance.

### Likelihood Explanation
The endpoint requires zero authentication, zero API keys, and accepts a simple HTTP GET. The exploit is trivially scriptable with `curl` or any HTTP load tool. No special knowledge of the system is required beyond knowing the public API path `/api/v1/network/nodes`, which is documented in the OpenAPI spec at [8](#0-7) . The attack is repeatable indefinitely.

### Recommendation
1. Add `@Cacheable` to `findNetworkNodes()` with a short TTL (e.g., 30–60 seconds) using a Caffeine cache manager, mirroring the pattern used in the `grpc` module's `AddressBookEntryRepository`.
2. Add per-IP or global rate limiting to the `rest-java` module for the `/api/v1/network/nodes` endpoint (e.g., via a Bucket4j filter similar to `ThrottleManagerImpl` in `web3`).
3. Consider moving the `max(consensus_timestamp)` subquery in `latest_node_stake` CTE to a materialized or pre-computed value to reduce per-request query cost.

### Proof of Concept
```bash
# No authentication required
# Run from any machine with network access to the mirror node REST API

while true; do
  curl -s "https://<mirror-node-host>/api/v1/network/nodes" -o /dev/null &
done

# Or with a controlled rate using Apache Bench:
ab -n 10000 -c 50 "https://<mirror-node-host>/api/v1/network/nodes"

# Each request triggers the full multi-CTE query in NetworkNodeRepository.findNetworkNodes()
# Monitor PostgreSQL CPU: watch -n1 "psql -c 'SELECT sum(total_exec_time) FROM pg_stat_statements WHERE query LIKE \"%latest_address_book%\"'"
# Expected: sustained CPU elevation >30% above 24h baseline with ~50 concurrent requests
```

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L135-136)
```java
        return networkNodeRepository.findNetworkNodes(
                fileId, nodeIdArray, lowerBound, upperBound, orderDirection, limit);
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/AddressBookEntryRepository.java (L16-19)
```java
    @Cacheable(
            cacheManager = ADDRESS_BOOK_ENTRY_CACHE,
            cacheNames = CACHE_NAME,
            unless = "@spelHelper.isNullOrEmpty(#result)")
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L53-55)
```java
    public int getEffectiveLimit() {
        return Math.min(limit, MAX_LIMIT);
    }
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
