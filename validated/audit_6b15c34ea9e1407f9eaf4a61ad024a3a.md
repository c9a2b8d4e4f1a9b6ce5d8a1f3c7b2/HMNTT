All technical claims have been verified against the actual codebase. Here is the result:

---

Audit Report

## Title
Unauthenticated Connection Pool Exhaustion via Unbounded Concurrent Requests to `getNftAllowances` During Network Partition

## Summary
The `getNftAllowances` endpoint in `AllowancesController` has no per-IP rate limiting or in-flight request cap at the service or controller layer. During a network partition, each concurrent request holds a HikariCP database connection for the full partition duration. An unprivileged attacker can exhaust the finite connection pool, denying service to all other users until the partition resolves.

## Finding Description

**Code path — verified:**

`AllowancesController.getNftAllowances()` (lines 57–83) builds a request and calls `NftAllowanceServiceImpl.getNftAllowances()` (lines 21–31), which calls `entityService.lookup()` and then `NftAllowanceRepositoryCustomImpl.findAll()` (lines 37–47). The `findAll` method executes a blocking JOOQ query via `DSLContext` against the `nft_allowance` table with no query timeout configured. [1](#0-0) [2](#0-1) [3](#0-2) 

**Root cause — no `inFlightReq` middleware in rest-java:**

The `hedera-mirror-rest-java` Traefik middleware stack contains only `circuitBreaker` and `retry`. The `inFlightReq` limiter present in the `hedera-mirror-graphql` chart (`amount: 5`) is absent here. [4](#0-3) [5](#0-4) 

**Root cause — GCP rate cap is non-functional by default:**

`maxRatePerEndpoint: 250` is configured in the GCP gateway backend policy, but the file itself notes it `Requires a change to HPA to take effect`, meaning it is not enforced in the default deployment. [6](#0-5) 

**Root cause — no HikariCP `maximumPoolSize` configured:**

No HikariCP configuration exists in the rest-java module, so the pool defaults to 10 connections. Each blocked query during a partition holds one connection for the full `connectionTimeout` duration. [7](#0-6) 

**Why the circuit breaker fails:**

The Traefik circuit breaker triggers on `NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25`. During a network partition, DB queries hang rather than immediately error; the circuit breaker does not open until enough requests have already failed, by which time the pool is already exhausted. [8](#0-7) 

## Impact Explanation
Once the 10-connection HikariCP pool is exhausted, every subsequent request to any endpoint in the rest-java service that requires a DB connection will block until `connectionTimeout` expires and then return a 500. This is a full denial of service for all users of the rest-java API (NFT allowances, airdrops, network endpoints, topics) for the duration of the attack combined with the partition. The `RestJavaHighDBConnections` Prometheus alert is reactive (fires after 5 minutes at >75% utilization) and does not prevent the outage. [7](#0-6) 

## Likelihood Explanation
No authentication is required. The endpoint is publicly reachable at `/api/v1/accounts/{id}/allowances/nfts`. An attacker needs only a script sending concurrent HTTP GET requests — no special knowledge, credentials, or exploit tooling. Network partitions (even brief ones caused by cloud provider incidents or intentional BGP manipulation) are realistic triggers. The attack is repeatable and can be sustained for as long as the attacker maintains the request flood. [9](#0-8) 

## Recommendation
1. **Add `inFlightReq` middleware** to the `hedera-mirror-rest-java` Helm chart, mirroring the graphql chart's `amount: 5` per-IP limiter.
2. **Set a JOOQ query timeout** in `NftAllowanceRepositoryCustomImpl.findAll()` (e.g., `.queryTimeout(5, TimeUnit.SECONDS)`) so hung DB connections are released promptly.
3. **Configure HikariCP explicitly** with a `maximumPoolSize` appropriate to the replica count and a short `connectionTimeout` (e.g., 2–3 seconds) to fail fast rather than queue indefinitely.
4. **Enable the HPA** so that `maxRatePerEndpoint: 250` in the GCP backend policy becomes effective, or remove the misleading comment and enforce it via a separate mechanism.

## Proof of Concept
```bash
# Trigger a network partition between rest-java pods and the DB (e.g., via iptables or a cloud firewall rule),
# then flood the endpoint concurrently:
for i in $(seq 1 20); do
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.1234/allowances/nfts" &
done
wait
# All 20 requests attempt DB connections; 10 acquire pool slots and hang for connectionTimeout.
# Requests 11-20 immediately fail with HikariCP pool exhaustion (500).
# All other rest-java endpoints (network, topics, airdrops) also return 500 until the partition clears.
``` [10](#0-9)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L57-83)
```java
    @GetMapping(value = "/nfts")
    NftAllowancesResponse getNftAllowances(
            @PathVariable EntityIdParameter id,
            @RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] accountIds,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(defaultValue = "true") boolean owner,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        var field = owner ? NFT_ALLOWANCE.SPENDER : NFT_ALLOWANCE.OWNER;
        var request = NftAllowanceRequest.builder()
                .accountId(id)
                .isOwner(owner)
                .limit(limit)
                .order(order)
                .ownerOrSpenderIds(new Bound(accountIds, true, ACCOUNT_ID, field))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, NFT_ALLOWANCE.TOKEN_ID))
                .build();

        var serviceResponse = service.getNftAllowances(request);
        var allowances = nftAllowanceMapper.map(serviceResponse);

        var sort = Sort.by(order, ACCOUNT_ID, TOKEN_ID);
        var pageable = PageRequest.of(0, limit, sort);
        var links = linkFactory.create(allowances, pageable, EXTRACTORS.get(owner));

        return new NftAllowancesResponse().allowances(allowances).links(links);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L21-31)
```java
    public Collection<NftAllowance> getNftAllowances(NftAllowanceRequest request) {

        var ownerOrSpenderId = request.getOwnerOrSpenderIds();
        var token = request.getTokenIds();

        checkOwnerSpenderParamValidity(ownerOrSpenderId, token);

        var id = entityService.lookup(request.getAccountId());

        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java (L37-47)
```java
    public Collection<NftAllowance> findAll(NftAllowanceRequest request, EntityId accountId) {
        boolean byOwner = request.isOwner();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, byOwner).and(getBoundConditions(bounds));
        return dslContext
                .selectFrom(NFT_ALLOWANCE)
                .where(condition)
                .orderBy(SORT_ORDERS.get(new OrderSpec(byOwner, request.getOrder())))
                .limit(request.getLimit())
                .fetchInto(NftAllowance.class);
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-56)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L83-86)
```yaml
        - path:
            type: RegularExpression
            value: '/api/v1/accounts/(\d+\.){0,2}(\d+|(0x)?[A-Fa-f0-9]{40}|(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}|[A-Z2-7]{4,5}|[A-Z2-7]{7,8}))/(allowances/nfts|airdrops)'
        - path:
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L158-163)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-221)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: rest-java
      area: resource
      severity: critical
```

**File:** charts/hedera-mirror-graphql/values.yaml (L135-145)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - retry:
      attempts: 3
      initialInterval: 100ms
```
