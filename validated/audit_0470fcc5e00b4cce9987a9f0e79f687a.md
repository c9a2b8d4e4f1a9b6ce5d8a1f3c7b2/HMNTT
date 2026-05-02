Based on my direct code investigation, all key technical claims in this report are verified against the actual source code. Here is my assessment:

---

# Audit Report

## Title
Unauthenticated High-Frequency Polling of `/api/v1/network/stake` Exhausts HikariCP Database Connection Pool

## Summary
The `GET /api/v1/network/stake` endpoint in the `rest-java` module executes a native SQL subquery against the database on every request with no caching, no rate limiting, and no authentication. A single unprivileged attacker flooding this endpoint can saturate the HikariCP connection pool, causing all database-dependent endpoints in the service to queue and time out.

## Finding Description

**Verified code path:**

`NetworkController.getNetworkStake()` (lines 126–130) calls `networkService.getLatestNetworkStake()`, which delegates directly to `networkStakeRepository.findLatest()` with no intermediate caching or throttling. [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` (lines 52–56) calls the repository unconditionally on every invocation. [2](#0-1) 

`NetworkStakeRepository.findLatest()` (lines 12–19) executes the following native SQL on every call:

```sql
select * from network_stake
where consensus_timestamp = (
    select max(consensus_timestamp) from network_stake
)
``` [3](#0-2) 

**Three absent defenses — all confirmed:**

1. **No caching.** A search across all `rest-java` main sources finds zero `@Cacheable` annotations and no `CacheManager` or `@EnableCaching` beans anywhere in the module. 

2. **No rate limiting.** The `rest-java` config directory (`JacksonConfiguration`, `LoggingFilter`, `MetricsConfiguration`, `MetricsFilter`, `NetworkProperties`, `RestJavaConfiguration`, `RuntimeHintsConfiguration`, `WebMvcConfiguration`) contains no throttle or rate-limit infrastructure. The only `ThrottleConfiguration` in the codebase lives exclusively in the `web3` module and is not wired into `rest-java`. [4](#0-3) 

3. **No authentication.** The endpoint is mapped with a plain `@GetMapping("/stake")` and no security annotation, filter, or Spring Security rule guards it. [5](#0-4) 

## Impact Explanation

Each concurrent request to `/api/v1/network/stake` acquires a HikariCP connection for the duration of the subquery. The `hedera-mirror-rest-java` Grafana dashboard explicitly monitors `hikaricp_connections_active`, `hikaricp_connections_idle`, and `hikaricp_connections_pending`, confirming HikariCP is the connection pool in use. [6](#0-5) 

When the pool is exhausted, all other endpoints sharing the same datasource (supply, nodes, exchange rate, fee schedule) also begin queuing and timing out. Clients constructing staking transactions cannot retrieve `staking_reward_rate`, `stake_total`, and related fields, directly impairing the ability to build valid staking transactions on the network.

## Likelihood Explanation

The endpoint requires no credentials, no API key, and accepts no parameters. A single `curl` loop or any HTTP benchmarking tool (`wrk`, `ab`, `hey`) run from a single machine is sufficient. The attack is stateless and trivially parallelizable across multiple source IPs. The subquery requires at minimum two index scans per call (one for `max(consensus_timestamp)`, one for the outer `WHERE`), meaning each request holds a connection slightly longer than a simple primary-key fetch, amplifying pool pressure per unit of attacker bandwidth.

## Recommendation

1. **Add response caching** at the service layer using `@Cacheable` with a short TTL (e.g., 30 seconds). Network stake data changes only once per staking period (~24 hours), so even a 30-second cache would eliminate nearly all redundant database hits.
2. **Add rate limiting** at the `rest-java` servlet filter or Spring MVC interceptor level, analogous to the bucket4j-based `ThrottleManagerImpl` already present in the `web3` module.
3. **Tune HikariCP pool size** and set an explicit `connectionTimeout` so pool exhaustion fails fast rather than queuing indefinitely.

## Proof of Concept

```bash
# Flood the endpoint from a single machine
hey -n 10000 -c 200 http://<mirror-node-host>/api/v1/network/stake

# Observe pool exhaustion in logs:
# HikariPool-1 - Connection is not available, request timed out after <N>ms
# All subsequent requests to /api/v1/network/supply, /nodes, etc. also time out
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L52-56)
```java
    public NetworkStake getLatestNetworkStake() {
        return networkStakeRepository
                .findLatest()
                .orElseThrow(() -> new EntityNotFoundException("No network stake data found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkStakeRepository.java (L12-19)
```java
    @Query(value = """
        select *
        from network_stake
        where consensus_timestamp = (
            select max(consensus_timestamp) from network_stake
        )
        """, nativeQuery = true)
    Optional<NetworkStake> findLatest();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-5)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.config;

import io.github.bucket4j.Bandwidth;
```

**File:** charts/hedera-mirror-common/dashboards/hedera-mirror-rest-java.json (L1-5)
```json
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
```
