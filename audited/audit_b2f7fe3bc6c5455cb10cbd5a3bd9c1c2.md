### Title
Unauthenticated, Rate-Limit-Free Bulk Enumeration of `pendingReward` via GraphQL `account()` Query

### Summary
The GraphQL `account()` resolver exposes `pendingReward` for any account with no authentication and no per-IP or per-session rate limiting. An unprivileged attacker can iterate through sequential account numbers and harvest the pending staking reward for every account on the network in an automated loop. Unlike the `web3` module which has a `ThrottleManagerImpl` backed by Bucket4j, the `graphql` module has no equivalent protection.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java`, lines 32–58:

```java
@QueryMapping
Optional<Account> account(@Argument @Valid AccountInput input) {
    ...
    if (entityId != null) {
        return entityService
                .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                .map(accountMapper::map);   // pendingReward is included in the mapped object
    }
    ...
}
```

The `pendingReward` field is declared in `graphql/src/main/resources/graphql/account.graphqls` (line 61) and `common.graphqls` (line 52) with no access-control directive.

**What protections exist and why they are insufficient:**

`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, lines 42–48:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
```

These controls limit the complexity and depth of a **single** GraphQL document. They do not limit the **rate** at which separate HTTP requests can be submitted. A trivial `{ account(input: { entityId: { shard:0, realm:0, num: N } }) { pendingReward } }` query has a complexity of 1–2 and a depth of 2, well within both thresholds.

There is no Spring Security configuration, no `@PreAuthorize`/`@Secured` annotation, no Bucket4j bucket, and no servlet filter performing rate limiting anywhere under `graphql/src/main/java/`. The `ThrottleManagerImpl` in `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java` is scoped exclusively to the `web3` module and is not wired into the `graphql` module.

**Root cause:** The `graphql` module was never given a rate-limiting layer. The per-query structural guards (`MaxQueryComplexityInstrumentation`, `MaxQueryDepthInstrumentation`, parser token limits) address abuse within a single request but provide zero protection against a high-volume sequence of individually cheap requests.

### Impact Explanation

An attacker can enumerate the `pendingReward` of every account on the Hedera network (account numbers are sequential integers starting at 1) by scripting thousands of requests per second. Concrete impacts:

1. **Bulk intelligence harvest** – complete mapping of which accounts hold large uncollected staking rewards, enabling targeted phishing, key-theft attempts, or front-running of reward-collection transactions.
2. **Service degradation / DoS** – each `account()` call triggers a database read; an unbounded flood of requests can saturate the mirror-node's database connection pool and degrade service for legitimate users.
3. **No cost to attacker** – no API key, no token, no credential is required; the attack is repeatable from any IP without consequence.

### Likelihood Explanation

Preconditions: none. The endpoint is publicly reachable at `/graphql/alpha` (confirmed in `charts/hedera-mirror-graphql/postman.json`, line 44). Account numbers are a predictable integer sequence. A single `curl` loop or a trivial Python script is sufficient. The attack is fully automatable, repeatable, and leaves no authentication trail.

### Recommendation

1. **Add a rate-limiting filter to the `graphql` module** using the same Bucket4j pattern already present in `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`. Apply a per-IP token-bucket limit (e.g., 10–20 requests/second) via a `OncePerRequestFilter` or Spring Security filter chain.
2. **Require an API key or bearer token** for the GraphQL endpoint, consistent with how the REST module handles authenticated users in `rest/middleware/authHandler.js`.
3. **Consider field-level cost weighting** so that `pendingReward` carries a higher complexity score in `MaxQueryComplexityInstrumentation`, making bulk field harvesting within a single query more expensive.
4. **Add CORS and IP-allowlist controls** at the ingress/load-balancer level as a defence-in-depth measure.

### Proof of Concept

```bash
# Enumerate pendingReward for accounts 0.0.1 through 0.0.100000
# No credentials, no rate limiting, runs at full network speed
for num in $(seq 1 100000); do
  curl -s -X POST http://<mirror-node-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ account(input: { entityId: { shard:0, realm:0, num:${num} } }) { pendingReward } }\"}" &
done
wait
```

Each request returns HTTP 200 with `{"data":{"account":{"pendingReward":<value>}}}` or `{"data":{"account":null}}` for non-existent accounts. No authentication header is required. No 429 response is ever returned because no rate-limiting layer exists in the `graphql` module.