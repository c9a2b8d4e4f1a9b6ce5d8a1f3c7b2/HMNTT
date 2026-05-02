### Title
Unauthenticated Resource Exhaustion via Uncached, Unthrottled Multi-CTE Query on `/api/v1/network/nodes`

### Summary
The `findNetworkNodes()` method in `NetworkNodeRepository.java` executes a multi-CTE native SQL query with correlated subqueries on every invocation, with no `@Cacheable` annotation and no rate limiting applied to the `/api/v1/network/nodes` endpoint in the `rest-java` module. An unprivileged external user can vary `nodeIds` or range parameters across rapid successive requests, forcing repeated full CTE evaluations against the database and exhausting database connection/CPU resources.

### Finding Description
**Code location**: `rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java`, lines 25–105, `findNetworkNodes()`.

**Root cause**: The `@Query`-annotated method has no `@Cacheable` annotation. Contrast this with the `grpc` module's `AddressBookEntryRepository.findByConsensusTimestampAndNodeId()` which is decorated with `@Cacheable(cacheManager = ADDRESS_BOOK_ENTRY_CACHE, ...)` — the rest-java `NetworkNodeRepository` has no equivalent.

The query itself is expensive:
- CTE `latest_address_book`: `ORDER BY start_consensus_timestamp DESC LIMIT 1` full scan
- CTE `latest_node_stake`: correlated subquery `(select max(consensus_timestamp) from node_stake)` on every execution
- Main query: per-row correlated subquery against `address_book_service_endpoint` for each result row

**Call chain**: `GET /api/v1/network/nodes` → `NetworkController.getNodes()` (line 152) → `NetworkServiceImpl.getNetworkNodes()` (line 100) → `networkNodeRepository.findNetworkNodes(...)` (line 135–136) — no caching at any layer.

**Rate limiting gap**: The `ThrottleConfiguration` / `ThrottleManagerImpl` (bucket4j-based) exists only in the `web3` module for contract-call endpoints. No equivalent throttle filter is wired into the `rest-java` module for this endpoint. The `rest-java/src/main/java/.../config/` directory contains only `JacksonConfiguration`, `LoggingFilter`, `MetricsFilter`, `NetworkProperties`, `RestJavaConfiguration`, `RuntimeHintsConfiguration`, and `WebMvcConfiguration` — none implement per-IP or per-endpoint rate limiting.

**Parameter variation**: The `nodeIds` array (passed as `Long[]`) and range bounds (`minNodeId`, `maxNodeId`) are user-controlled. Each unique combination produces a distinct query plan execution. The `fileId` is constrained to `EQ` operator only (controller line 155–157), but the valid values (101, 102) are known and the `nodeIds` parameter alone provides sufficient variation.

### Impact Explanation
Each request forces: (1) a full `address_book` table scan with sort, (2) a `MAX()` aggregate over `node_stake`, (3) per-row correlated subqueries against `address_book_service_endpoint`. Under sustained concurrent load with varied `nodeIds` parameters, this saturates database CPU and connection pool, degrading or denying service to all consumers of the mirror node REST API. The `node_stake` correlated subquery (`select max(consensus_timestamp) from node_stake`) is particularly costly as it re-executes for every CTE materialization.

### Likelihood Explanation
The endpoint is public and unauthenticated. No API key, session token, or privilege is required. The attack is trivially scriptable: cycle through `node.id=0`, `node.id=1`, … `node.id=N` or vary `node.id=gte:X` with incrementing `X`. A single attacker with a modest HTTP client can sustain hundreds of unique-parameter requests per second. The absence of any rate limiting in the `rest-java` module makes this repeatable indefinitely.

### Recommendation
1. Add `@Cacheable` to `findNetworkNodes()` with a short TTL (e.g., 30–60 seconds), keyed on all parameters. Address book data changes infrequently.
2. Implement per-IP rate limiting (e.g., bucket4j filter) in the `rest-java` module for the `/api/v1/network/nodes` endpoint, mirroring the pattern in `web3/ThrottleConfiguration`.
3. Consider materializing the `latest_node_stake` CTE as a pre-computed view or scheduled cache to avoid the `MAX()` correlated subquery on every request.

### Proof of Concept
```bash
# Vary nodeIds to prevent any hypothetical future cache from serving hits
for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/network/nodes?node.id=${i}" &
done
wait

# Alternatively, vary the lower range bound
for i in $(seq 0 500); do
  curl -s "https://<mirror-node-host>/api/v1/network/nodes?node.id=gte:${i}" &
done
wait
```

Each request hits `findNetworkNodes()` directly with no cache interception, executing the full multi-CTE query. Under concurrent load, database CPU and connection pool exhaustion will manifest as increased latency and eventual 503 errors for all API consumers.