I verified all technical claims against the actual codebase. Here is my assessment:

**All code references are accurate:**

- `HooksController.getHooks()` accepts `EntityIdParameter ownerId` at line 82. [1](#0-0) 
- `HookServiceImpl.getHooks()` calls `entityService.lookup(request.getOwnerId())` at line 35. [2](#0-1) 
- `EntityServiceImpl.lookup()` dispatches to `entityRepository.findByAlias(p.alias())` for alias parameters at line 33. [3](#0-2) 
- `rest-java/EntityRepository.findByAlias()` is a plain `@Query` with no `@Cacheable`. [4](#0-3) 
- `web3/EntityRepository` has `@Cacheable` on alias lookups; `rest-java` does not. [5](#0-4) 
- `ThrottleConfiguration` exists only in the `web3` module. [6](#0-5) 
- `ALIAS_REGEX` only validates syntax. [7](#0-6) 

---

# Audit Report

## Title
Uncached Alias-Based Entity Lookup Enables DB Resource Exhaustion via `getHooks()` Endpoint

## Summary
The `/api/v1/accounts/{ownerId}/hooks` endpoint in the `rest-java` module performs an uncached native SQL query against the `entity` table on every request when `ownerId` is supplied as an alias. With no rate limiting present in the module, an unauthenticated attacker can sustain a high-frequency stream of distinct alias lookups, each forcing a full database round-trip.

## Finding Description
**Exact code path:**

1. `HooksController.getHooks()` accepts `{ownerId}` as `EntityIdParameter`, which resolves to `EntityIdAliasParameter` when the value matches `ALIAS_REGEX` (`^((\\d{1,5})\\.)?((\\d{1,5})\\.)?([A-Z2-7]{40,70})$`). [1](#0-0) [7](#0-6) 

2. `HookServiceImpl.getHooks()` unconditionally calls `entityService.lookup(request.getOwnerId())` before any other logic. [8](#0-7) 

3. `EntityServiceImpl.lookup()` dispatches to `entityRepository.findByAlias(p.alias())` for alias-typed parameters. [9](#0-8) 

4. `rest-java`'s `EntityRepository.findByAlias()` is a plain native `@Query` with no `@Cacheable` annotation — every invocation hits the database directly. [4](#0-3) 

**Root cause:** The `rest-java` `EntityRepository` deliberately omits the `@Cacheable` annotation that `web3` applies to equivalent alias lookups. The `ThrottleConfiguration`/`ThrottleManager` infrastructure exists exclusively in the `web3` module and is not applied to `rest-java` controllers. [5](#0-4) 

**Why existing checks fail:** The only input validation is the `ALIAS_REGEX` pattern check in `EntityIdAliasParameter.valueOfNullable()`, which confirms syntactic validity only. It does not prevent repeated or high-volume requests. There is no per-IP, per-endpoint, or global rate limit applied to `HooksController`. [10](#0-9) 

## Impact Explanation
Each request with an alias-based `ownerId` forces a `SELECT id FROM entity WHERE alias = ? AND deleted <> true` query against the `entity` table. With no caching and no rate limiting, an attacker can drive a sustained, high-frequency query load against the database. Because each alias is distinct, no query result can be reused. This directly increases database CPU, I/O, and connection pool utilization. On a production node with a large `entity` table, sustained parallel requests from even a single client can measurably degrade service for all users.

## Likelihood Explanation
The attack requires zero privileges. The endpoint is publicly accessible, the alias format is documented and trivially constructable, and valid aliases can be enumerated from on-chain data. A single attacker with a modest HTTP client (`wrk`, `ab`, or a simple script) can issue hundreds of requests per second. The attack is repeatable, requires no authentication, and leaves no persistent side effects.

## Recommendation
1. **Add caching** to `rest-java`'s `EntityRepository.findByAlias()` using Spring's `@Cacheable` with a short TTL (e.g., 30–60 seconds), consistent with how `web3`'s `EntityRepository` handles alias lookups.
2. **Add rate limiting** to the `rest-java` module — either at the application level (e.g., Bucket4j, Resilience4j) or at the infrastructure level (reverse proxy / API gateway) — targeting the `/api/v1/accounts/{ownerId}/hooks` endpoint and other public endpoints that trigger DB lookups.
3. Consider applying both controls together, as caching alone does not protect against distinct-alias cycling.

## Proof of Concept
```bash
# Generate distinct valid base32 aliases and hammer the endpoint
for i in $(seq 1 1000); do
  ALIAS=$(python3 -c "import base64, os; print(base64.b32encode(os.urandom(20)).decode().rstrip('='))")
  curl -s "https://<mirror-node>/api/v1/accounts/${ALIAS}/hooks" &
done
wait
```
Each request resolves to a unique alias, bypasses any potential cache, and issues a fresh `SELECT` against the `entity` table. Sustained execution will increase DB CPU and connection pool utilization measurably above baseline.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L80-90)
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
        final var hooksServiceResponse = hookService.getHooks(hooksRequest);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L32-36)
```java
    public Collection<Hook> getHooks(HooksRequest request) {
        final var sort = Sort.by(request.getOrder(), HOOK_ID);
        final var page = PageRequest.of(0, request.getLimit(), sort);
        final var id = entityService.lookup(request.getOwnerId());
        final long lowerBound = request.getLowerBound();
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByAlias(byte[] alias);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L39-44)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_ALIAS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    @Query(value = """
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdAliasParameter.java (L13-14)
```java
    public static final String ALIAS_REGEX = "^((\\d{1,5})\\.)?((\\d{1,5})\\.)?([A-Z2-7]{40,70})$";
    public static final Pattern ALIAS_PATTERN = Pattern.compile(ALIAS_REGEX);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdAliasParameter.java (L17-21)
```java
    static @Nullable EntityIdAliasParameter valueOfNullable(String id) {
        var aliasMatcher = ALIAS_PATTERN.matcher(id);

        if (!aliasMatcher.matches()) {
            return null;
```
