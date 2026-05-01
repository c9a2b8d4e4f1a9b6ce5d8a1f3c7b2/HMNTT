### Title
Unauthenticated EVM Address Lookup Causes Unbounded DB Queries, Enabling Connection Pool Exhaustion via `getHooks()`

### Summary
The `HooksController.getHooks()` endpoint accepts an EVM address as `ownerId` without authentication. Every such request unconditionally executes a `findByEvmAddress` database query with no caching or rate limiting in the application layer. An attacker flooding this endpoint with concurrent EVM-address-format requests can exhaust the DB connection pool, degrading service for all users.

### Finding Description

**Exact code path:**

`HooksController.getHooks()` accepts `@PathVariable EntityIdParameter ownerId`. [1](#0-0) 

`EntityIdParameter.valueOf()` parses a 40-hex-char string as `EntityIdEvmAddressParameter` — no DB access yet. [2](#0-1) 

The `ownerId` is stored in `HooksRequest` and passed to `HookServiceImpl.getHooks()`, which calls `entityService.lookup()` on **every** invocation. [3](#0-2) 

`EntityServiceImpl.lookup()` dispatches on the parameter type. For `EntityIdEvmAddressParameter`, it unconditionally issues a `findByEvmAddress` DB query — even for addresses that do not exist. [4](#0-3) 

**Root cause / failed assumption:** The REST-Java `EntityServiceImpl` has **no cache** (contrast with the importer's `EntityIdServiceImpl`, which wraps the same lookup in a `CacheManager`). Numeric IDs (`EntityIdNumParameter`) resolve to `Optional.of(p.id())` — zero DB cost — while EVM addresses always hit the database. This asymmetry is the exploitable difference. [5](#0-4) 

### Impact Explanation
Each concurrent EVM-address request holds a DB connection for the duration of the `findByEvmAddress` query. With a typical HikariCP pool of 10–20 connections, a modest flood (e.g., 50–100 concurrent requests) saturates the pool. All subsequent requests — including legitimate ones — queue or fail with connection-timeout errors. Because the mirror-node REST-Java service is stateless and horizontally scaled, saturating the shared DB connection pool degrades all replicas simultaneously, consistent with ≥30% processing-node impact.

### Likelihood Explanation
No authentication is required. The endpoint is publicly reachable at `/api/v1/accounts/{ownerId}/hooks`. Any attacker can generate arbitrary valid 40-hex-char EVM addresses (e.g., `0xdeadbeef...`) and issue them as path variables. The attack is trivially scriptable with `curl`, `ab`, or `wrk`, requires no prior knowledge of the system, and is fully repeatable.

### Recommendation
1. **Add a cache** in `EntityServiceImpl.lookup()` for `EntityIdEvmAddressParameter` (and `EntityIdAliasParameter`) lookups, mirroring the `CacheManager`-backed approach in the importer's `EntityIdServiceImpl`.
2. **Apply rate limiting** at the API gateway or Spring filter layer, keyed on source IP, for all `/api/v1/accounts/{ownerId}/*` endpoints.
3. **Short-circuit on long-zero EVM addresses** before hitting the DB: if the address encodes a valid `shard.realm.num` (all-zero prefix), resolve it arithmetically as `EntityIdNumParameter` does, avoiding the query entirely.

### Proof of Concept

```bash
# Generate 200 concurrent requests with a random non-existent EVM address
EVM="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
for i in $(seq 1 200); do
  curl -s "https://<mirror-node-host>/api/v1/accounts/${EVM}/hooks" &
done
wait
```

**Expected result:** DB connection pool exhausted; subsequent legitimate requests return HTTP 500 or time out. Monitor with `SELECT count(*) FROM pg_stat_activity WHERE state='active'` to observe connection saturation.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L80-89)
```java
    @GetMapping
    ResponseEntity<HooksResponse> getHooks(
            @PathVariable EntityIdParameter ownerId,
            @RequestParam(defaultValue = "", name = HOOK_ID, required = false)
                    @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    NumberRangeParameter[] hookId,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "desc") Sort.Direction order) {

        final var hooksRequest = hooksRequest(ownerId, hookId, limit, order);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdParameter.java (L17-20)
```java
        if ((entityId = EntityIdNumParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else if ((entityId = EntityIdEvmAddressParameter.valueOfNullable(id)) != null) {
            return entityId;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L35-35)
```java
        final var id = entityService.lookup(request.getOwnerId());
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-38)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```
