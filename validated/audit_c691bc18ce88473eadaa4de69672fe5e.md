All primary code claims have been verified against the actual source. Here is the result:

---

# Audit Report

## Title
Unauthenticated High-Frequency Flooding of `/api/v1/network/stake` Exhausts HikariCP Connection Pool in rest-java

## Summary
The `GET /api/v1/network/stake` endpoint in the rest-java service issues a live database query on every request with no application-level rate limiting and no result caching. Under a sustained flood from an unauthenticated attacker, the shared HikariCP connection pool is exhausted, causing all other rest-java endpoints to block and time out, effectively taking the service offline.

## Finding Description

**`NetworkController.getNetworkStake()` — no throttle guard**

The handler at lines 126–130 is a plain `@GetMapping` with no rate-limit annotation, no token-bucket check, and no guard of any kind: [1](#0-0) 

**`NetworkServiceImpl.getLatestNetworkStake()` — no caching**

The service method at lines 51–56 delegates directly to the repository on every call. No `@Cacheable` or any other caching annotation is present: [2](#0-1) 

**`NetworkStakeRepository.findLatest()` — live native SQL on every invocation**

The repository executes a correlated subquery (`SELECT * FROM network_stake WHERE consensus_timestamp = (SELECT MAX(...) FROM network_stake)`) via JPA on every call, acquiring a HikariCP connection each time. No `@Cacheable` is present: [3](#0-2) 

**No rate-limiting infrastructure in rest-java**

`ThrottleConfiguration` exists only in the `web3` module:



The rest-java `config/` package contains only `JacksonConfiguration`, `LoggingFilter`, `MetricsConfiguration`, `MetricsFilter`, `NetworkProperties`, `RestJavaConfiguration`, `RuntimeHintsConfiguration`, and `WebMvcConfiguration` — no throttle bean:



**Contrast with grpc module — `@Cacheable` is used there**

The grpc module's equivalent `NodeStakeRepository.findAllStakeByConsensusTimestamp()` is annotated with `@Cacheable`, demonstrating the pattern is known and intentionally applied elsewhere but omitted in rest-java: [4](#0-3) 

**No HikariCP override in rest-java resources**

The only file under `rest-java/src/main/resources/` is `banner.txt` — no `application.yml` or `application.properties` overrides `spring.datasource.hikari.maximumPoolSize`, leaving HikariCP at its default of **10 connections**: [5](#0-4) 

## Impact Explanation
With a default pool of 10 connections and no rate limiting or caching, a flood of ~50–100 concurrent requests/second to `GET /api/v1/network/stake` holds all HikariCP connections busy executing the native SQL query. Every other rest-java endpoint (`/api/v1/network/nodes`, `/api/v1/network/supply`, `/api/v1/transactions`, etc.) blocks at `HikariPool.getConnection()` until the configured `connectionTimeout` (HikariCP default: 30 s) elapses, returning 500 errors to all legitimate users. The entire rest-java service becomes unavailable for the duration of the attack.

## Likelihood Explanation
The endpoint requires no authentication, accepts no parameters, and is publicly documented. Any attacker with a basic HTTP flood tool (`wrk`, `ab`, `hey`) can trigger this with a single command. No credentials, tokens, or special knowledge are required. The attack is trivially repeatable and can be sustained indefinitely.

## Recommendation
Apply at least one of the following mitigations:

1. **Add `@Cacheable` to `NetworkStakeRepository.findLatest()`** — `network_stake` is updated only once per staking period (~24 h), so a short TTL cache (e.g., 60 s) eliminates virtually all DB hits under flood conditions, matching the pattern already used in the grpc module's `NodeStakeRepository`.
2. **Add application-level rate limiting** — Port the existing `ThrottleConfiguration`/`ThrottleManagerImpl`/`ThrottleProperties` bucket4j infrastructure from the `web3` module into rest-java, or apply a per-IP rate limit at the ingress/API-gateway layer.
3. **Increase `maximumPoolSize` and set a short `connectionTimeout`** — A larger pool and a short timeout (e.g., 2–3 s) reduce blast radius but do not eliminate the root cause.

## Proof of Concept
```bash
# Flood the unauthenticated endpoint with 100 concurrent connections
wrk -t10 -c100 -d60s https://<mirror-node-host>/api/v1/network/stake

# Observe that concurrent requests to other endpoints begin timing out:
curl -v https://<mirror-node-host>/api/v1/network/nodes
# → 500 Internal Server Error (HikariPool connection timeout)
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L126-130)
```java
    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L51-56)
```java
    @Override
    public NetworkStake getLatestNetworkStake() {
        return networkStakeRepository
                .findLatest()
                .orElseThrow(() -> new EntityNotFoundException("No network stake data found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkStakeRepository.java (L10-19)
```java
public interface NetworkStakeRepository extends CrudRepository<NetworkStake, Long> {

    @Query(value = """
        select *
        from network_stake
        where consensus_timestamp = (
            select max(consensus_timestamp) from network_stake
        )
        """, nativeQuery = true)
    Optional<NetworkStake> findLatest();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L24-28)
```java
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
```

**File:** rest-java/src/main/resources/banner.txt (L1-1)
```text

```
