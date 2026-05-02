### Title
Unauthenticated, Uncached `findByEvmAddress` DB Query Enables Sustained DB CPU Exhaustion via GraphQL

### Summary
The `getByEvmAddressAndType()` method in `EntityServiceImpl` routes any EVM address whose first 4 bytes are non-zero directly to `entityRepository.findByEvmAddress()`, which executes an uncached SQL query against the `entity` table on every call. Because the GraphQL endpoint requires no authentication and has no application-level rate limiting, an unprivileged attacker can sustain a continuous stream of distinct, valid EVM addresses that always bypass the cheap `findById` path and force repeated DB queries, increasing DB CPU load above the 30% threshold over the 24-hour baseline.

### Finding Description

**Exact code path:**

`AccountController.account()` → `EntityService.getByEvmAddressAndType()` → `EntityRepository.findByEvmAddress()`

In `getByEvmAddressAndType()`:

```java
// EntityServiceImpl.java lines 34-41
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // line 37
        return entityRepository.findById(buffer.getLong())...;     // fast PK path
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)...;  // line 40 — DB query
}
``` [1](#0-0) 

The fast path (line 37) is only taken when bytes 0–11 of the 20-byte address are all zero. Any address with a non-zero value in bytes 0–3 (the first `int`) unconditionally falls through to `findByEvmAddress()` at line 40.

The repository query executed is:

```sql
select * from entity where evm_address = ?1 and deleted is not true
``` [2](#0-1) 

**Root cause — no caching on this repository method:** The graphql module's `EntityRepository` has zero `@Cacheable` annotations. Compare this to the web3 module's `EntityRepository`, which caches `findByEvmAddressAndDeletedIsFalse` with `@Cacheable`. Every call to the graphql `findByEvmAddress` hits the database unconditionally. [3](#0-2) 

**No application-level rate limiting:** A search across all graphql Java sources finds no `@RateLimiter`, no per-IP throttle, and no connection-count guard. The only protections configured are query complexity (`MaxQueryComplexityInstrumentation(200)`) and depth (`MaxQueryDepthInstrumentation(10)`) limits, which constrain the shape of a single query but impose no limit on the *rate* of requests. [4](#0-3) 

The `CacheProperties` cache (`expireAfterWrite=1h,maximumSize=1000`) applies only to parsed GraphQL documents via `CachedPreparsedDocumentProvider`, not to entity lookups. [5](#0-4) 

**No authentication on the endpoint:** `AccountController` carries no security annotation; the endpoint is publicly reachable. [6](#0-5) 

### Impact Explanation

Each request with a non-zero byte in positions 0–3 of the EVM address causes one synchronous DB query. Because results are never cached, identical addresses sent repeatedly each produce a fresh query. At a sustained moderate rate (e.g., hundreds of requests per second from a single host or a small botnet), the cumulative DB CPU load can exceed the 30% threshold over the 24-hour baseline. The `entity` table is a core shared table; elevated scan load on it degrades all other mirror-node services that depend on the same database.

### Likelihood Explanation

The attack requires no credentials, no special knowledge, and no brute-force volume. The attacker only needs to:
1. Know the GraphQL endpoint URL (publicly documented).
2. Send any 40-hex-char address with a non-zero first byte (e.g., `"0100000000000000000000000000000000000000"`).

This is trivially scriptable, repeatable indefinitely, and requires no prior account or API key. The absence of any application-level rate limiting means the attacker can sustain the load as long as desired.

### Recommendation

1. **Add caching to `EntityRepository.findByEvmAddress()`** in the graphql module, mirroring the web3 module's `@Cacheable` pattern, so repeated lookups of the same address do not hit the DB.
2. **Implement per-IP or per-client rate limiting** at the application layer (e.g., Spring's `RateLimiter` or a Bucket4j filter on the `/graphql` endpoint) to cap the number of requests per time window.
3. **Ensure a database index exists on `entity.evm_address`** so that even uncached queries are index scans rather than sequential scans.

### Proof of Concept

```bash
# Send 500 requests/second with a non-zero first byte (bypasses findById fast path)
# Each request forces: SELECT * FROM entity WHERE evm_address = '\x01...' AND deleted IS NOT TRUE

while true; do
  curl -s -X POST https://<mirror-node>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ account(input:{evmAddress:\"0100000000000000000000000000000000000001\"}){id} }"}' \
    &
done
```

Preconditions: No authentication, no rate limiting in place.
Trigger: Any valid 40-char hex address with bytes 0–3 non-zero.
Result: Every request executes `SELECT * FROM entity WHERE evm_address = ? AND deleted IS NOT TRUE` with no cache hit, sustaining DB CPU load proportional to request rate.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L1-18)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.graphql.repository;

import java.util.Optional;
import org.hiero.mirror.common.domain.entity.Entity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.graphql.data.GraphQlRepository;

@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-49)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CacheProperties.java (L13-16)
```java
public class CacheProperties {
    @NotBlank
    private String query = "expireAfterWrite=1h,maximumSize=1000,recordStats";
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L32-55)
```java
    @QueryMapping
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
        }

        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
```
