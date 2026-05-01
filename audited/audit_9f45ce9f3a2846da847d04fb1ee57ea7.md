### Title
Unauthenticated Alias Lookup Causes Unbounded DB Reads in `getNftAllowances()`

### Summary
Any unauthenticated caller can supply a non-existent alias or EVM address as the `{id}` path parameter to `GET /api/v1/accounts/{id}/allowances/nfts`. Each such request causes `EntityServiceImpl.lookup()` to execute a raw database query with no caching and no rate limiting, returning empty and throwing `EntityNotFoundException`. Because the rest-java service has no negative-result cache and no request throttle, an attacker can flood the endpoint with unique non-existent aliases to exhaust DB connection pool resources and degrade service for legitimate users.

### Finding Description

**Exact code path:**

`AllowancesController.getNftAllowances()` passes the path variable directly to the service: [1](#0-0) 

`NftAllowanceServiceImpl.getNftAllowances()` calls `entityService.lookup()` unconditionally before any repository query: [2](#0-1) 

`EntityServiceImpl.lookup()` dispatches to raw DB queries for alias and EVM address inputs, with no caching: [3](#0-2) 

The `rest-java` `EntityRepository` has no `@Cacheable` annotation on either lookup method: [4](#0-3) 

When the alias/EVM address is not found, `orElseThrow` fires `EntityNotFoundException`, which `GenericControllerAdvice` maps to HTTP 404: [5](#0-4) 

**Root cause / failed assumption:** The code assumes that callers will supply valid, existing aliases. There is no negative-result cache and no application-level rate limiter in the rest-java module (contrast: `web3` has `ThrottleManagerImpl` with a bucket-based RPS limiter; `web3/EntityRepository` has `@Cacheable` on alias lookups; `importer/EntityIdServiceImpl` has `cacheLookup`). The rest-java service has none of these defenses.

### Impact Explanation
Each request with a non-existent alias or EVM address issues a full SQL query (`SELECT id FROM entity WHERE alias = ? AND deleted <> true`) against the database. An attacker sending N requests per second with distinct non-existent aliases causes N DB queries per second with zero cache hits. This consumes DB connection pool slots and CPU, increasing query latency for all concurrent legitimate requests. The impact is service degradation (griefing) with no economic damage to on-chain state.

### Likelihood Explanation
No privileges, API keys, or on-chain accounts are required. The endpoint is publicly documented in the OpenAPI spec. An attacker needs only an HTTP client and the ability to generate arbitrary byte strings formatted as aliases (e.g., base32-encoded public keys or 20-byte hex EVM addresses). The attack is trivially scriptable, repeatable, and can be distributed across multiple source IPs to bypass any upstream IP-based rate limiting.

### Recommendation
1. **Add a negative-result cache** in `EntityServiceImpl.lookup()` (or at the `EntityRepository` level via `@Cacheable`) for alias and EVM address lookups, with a short TTL (e.g., 30s). This prevents repeated DB hits for the same non-existent alias.
2. **Add application-level rate limiting** to the rest-java service, mirroring the `ThrottleManagerImpl` pattern already present in the web3 module.
3. Alternatively, short-circuit at the controller layer by validating alias format/length before invoking the service, rejecting structurally invalid inputs with HTTP 400 before any DB access.

### Proof of Concept

```bash
# Generate unique non-existent EVM addresses and flood the endpoint
for i in $(seq 1 10000); do
  ADDR=$(printf '%040x' $RANDOM$RANDOM$RANDOM)
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.${ADDR}/allowances/nfts" &
done
wait
```

Each request triggers `entityRepository.findByEvmAddress()` with a unique address, guaranteeing a cache miss on every call. Observe DB query rate and connection pool saturation increasing linearly with request rate, with no application-level throttle to stop it.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L75-75)
```java
        var serviceResponse = service.getNftAllowances(request);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L28-28)
```java
        var id = entityService.lookup(request.getAccountId());
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L11-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {

    @Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByAlias(byte[] alias);

    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java (L115-118)
```java
    @ExceptionHandler
    private ResponseEntity<Object> notFound(final EntityNotFoundException e, final WebRequest request) {
        return handleExceptionInternal(e, null, null, NOT_FOUND, request);
    }
```
