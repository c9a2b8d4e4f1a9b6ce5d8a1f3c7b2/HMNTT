After verifying every code reference in the claim against the actual repository, all technical assertions hold. Here is the audit result:

---

# Audit Report

## Title
Unauthenticated Repeated Full-Range DB Scan via `GET /api/v1/network/registered-nodes` with No Caching or Rate Limiting

## Summary
The `GET /api/v1/network/registered-nodes` endpoint in the `rest-java` module is publicly reachable with no authentication, no server-side response caching, and no rate-limiting infrastructure. When called with no query parameters, the service resolves the node-ID range to `[0, Long.MAX_VALUE]` and issues a native SQL query against the `registered_node` table on every request. An unprivileged attacker sending a sustained stream of filter-free requests can drive repeated full-range index scans, increasing DB I/O above the baseline.

## Finding Description

**1. Unauthenticated endpoint**

`NetworkController.getRegisteredNodes()` is mapped at `@GetMapping("/registered-nodes")` with no `@PreAuthorize`, no security filter, and no authentication guard anywhere in the `rest-java` config layer. [1](#0-0) 

A search of `rest-java/src/main/java/org/hiero/mirror/restjava/config/` confirms there is no `SecurityConfig` class in this module.


**2. Default empty filter resolves to widest possible range**

`RegisteredNodesRequest.registeredNodeIds` defaults to `List.of()`. [2](#0-1) 

`NetworkServiceImpl.resolveRegisteredNodeIdBounds()` initialises `lowerBound = 0L` and `upperBound = MAX_VALUE`. When the input list is empty the loop body never executes, so `Range.closed(0L, Long.MAX_VALUE)` is returned unconditionally. [3](#0-2) 

**3. Native SQL query with full-range bounds**

`RegisteredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()` executes a native query:
```sql
select * from registered_node
where registered_node_id >= :lowerBound
  and registered_node_id <= :upperBound
  and deleted is false
  and (:type is null or type @> array[:type]::smallint[])
```
With `lowerBound = 0`, `upperBound = 9223372036854775807`, and `type = null`, this is a full primary-key-range index scan. The `LIMIT` (max 100) is applied after predicate evaluation; rows must still be visited until 100 non-deleted rows are found. [4](#0-3) 

**4. No server-side caching**

The only caching-adjacent mechanism in `rest-java` is `ShallowEtagHeaderFilter`, registered for `/api/*`. [5](#0-4) 

This filter computes ETags **after** the full DB query has already executed. It only avoids sending the response body to cooperative clients; it does not prevent the DB query from running on every request. No `@Cacheable` annotation exists on `NetworkServiceImpl.getRegisteredNodes()` or the repository method.

**5. No rate limiting in `rest-java`**

`ThrottleConfiguration` and `ThrottleManagerImpl` exist exclusively in the `web3` module and are not wired into `rest-java`. [6](#0-5) 

**6. MAX_LIMIT = 100 confirmed** [7](#0-6) 

## Impact Explanation

Every unauthenticated, filter-free request causes the DB to perform a full primary-key-range index scan of `registered_node`, applying the `deleted IS FALSE` heap filter on each visited row until 100 non-deleted rows are found. As the table grows (history rows accumulate), each scan becomes more expensive. A sustained moderate request rate from a single client or small botnet can push DB read I/O and CPU measurably above the 24-hour baseline, degrading query latency for all other consumers of the same DB instance.

## Likelihood Explanation

No credentials, API keys, or special network access are required. The endpoint is publicly documented in the OpenAPI spec. A k6 load-test script for this exact endpoint already exists in the repository, demonstrating the pattern. [8](#0-7) 

Any external actor can discover and script repeated calls. No brute-force or credential guessing is needed; the attack is purely volumetric GET requests to a single URL.

## Recommendation

1. **Rate limiting**: Wire a rate-limit interceptor (or reuse/adapt `ThrottleManagerImpl` from `web3`) into the `rest-java` filter chain, keyed on client IP or API key, for all `/api/v1/network/*` endpoints.
2. **Server-side caching**: Add `@Cacheable` (with a short TTL, e.g. 30–60 s) to `NetworkServiceImpl.getRegisteredNodes()`. The `registered_node` table changes infrequently, making it an ideal caching candidate.
3. **Require at least one filter**: Consider rejecting requests that supply neither `registerednode.id` nor `type`, or defaulting to a narrower range, to prevent unbounded scans.
4. **Infrastructure-level protection**: Ensure an API gateway or load balancer enforces per-IP request rate limits in front of the `rest-java` service.

## Proof of Concept

```bash
# No credentials, no filters — triggers full-range scan on every call
for i in $(seq 1 500); do
  curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes" -o /dev/null &
done
wait
```

Each concurrent request independently executes:
```sql
SELECT * FROM registered_node
WHERE registered_node_id >= 0
  AND registered_node_id <= 9223372036854775807
  AND deleted IS FALSE
  AND (NULL IS NULL OR type @> array[NULL]::smallint[])
LIMIT 100;
```
with no server-side cache hit and no rate-limit rejection, driving repeated full-range index scans against the DB.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L173-187)
```java
    @GetMapping("/registered-nodes")
    RegisteredNodesResponse getRegisteredNodes(@RequestParameter RegisteredNodesRequest request) {
        final var registeredNodes = networkService.getRegisteredNodes(request);
        final var registeredNodeDtos = registeredNodeMapper.map(registeredNodes);

        final var sort = Sort.by(request.getOrder(), REGISTERED_NODE_ID);
        final var pageable = PageRequest.of(0, request.getLimit(), sort);
        final var links = linkFactory.create(registeredNodeDtos, pageable, REGISTERED_NODE_EXTRACTOR);

        final var response = new RegisteredNodesResponse();
        response.setRegisteredNodes(registeredNodeDtos);
        response.setLinks(links);

        return response;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L42-44)
```java
    @RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
    @Size(max = 2)
    private List<NumberRangeParameter> registeredNodeIds = List.of();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L154-176)
```java
    private static Range<Long> resolveRegisteredNodeIdBounds(List<NumberRangeParameter> registeredNodeIdRanges) {
        long lowerBound = 0L;
        long upperBound = MAX_VALUE;

        for (final var range : registeredNodeIdRanges) {
            if (range.operator() == RangeOperator.EQ) {
                if (registeredNodeIdRanges.size() > 1) {
                    throw new IllegalArgumentException("The 'eq' operator cannot be combined with other operators");
                }
                return Range.closed(range.value(), range.value());
            } else if (range.hasLowerBound()) {
                lowerBound = Math.max(lowerBound, range.getInclusiveValue());
            } else if (range.hasUpperBound()) {
                upperBound = Math.min(upperBound, range.getInclusiveValue());
            }
        }

        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("Invalid range: lower bound exceeds upper bound");
        }

        return Range.closed(lowerBound, upperBound);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java (L14-22)
```java
    @Query(value = """
            select * from registered_node
            where registered_node_id >= :lowerBound
            and registered_node_id <= :upperBound
            and deleted is false
            and (:type is null or type @> array[:type]::smallint[])
            """, nativeQuery = true)
    List<RegisteredNode> findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
            long lowerBound, long upperBound, @Nullable Short type, Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-5)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.config;

import io.github.bucket4j.Bandwidth;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L35-35)
```java
    public static final int MAX_LIMIT = 100;
```

**File:** tools/k6/src/rest-java/test/networkRegisteredNodes.js (L1-5)
```javascript
// SPDX-License-Identifier: Apache-2.0

import http from 'k6/http';

import {isValidListResponse, RestJavaTestScenarioBuilder} from '../libex/common.js';
```
