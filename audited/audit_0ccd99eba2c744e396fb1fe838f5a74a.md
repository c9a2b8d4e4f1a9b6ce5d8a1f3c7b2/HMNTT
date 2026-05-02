### Title
GraphQL Query Cache Exhaustion via Comment-Variant Cache Key Pollution

### Summary
The `CachedPreparsedDocumentProvider` uses the raw, un-normalized query string as the cache key. An unauthenticated attacker can send semantically identical queries with unique comment suffixes (e.g., `# 1`, `# 2`, …), each of which occupies a distinct cache slot. With a hard cap of 1000 entries, the attacker can fill the entire cache with junk entries, evicting legitimate cached queries and forcing every real request to incur full parse-and-validate overhead on every call.

### Finding Description
**Exact code path:**

`CachedPreparsedDocumentProvider.java`, line 26:
```java
return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
```
The cache key is `executionInput.getQuery()` — the verbatim, raw query string submitted by the client. No normalization (comment stripping, whitespace collapsing, AST fingerprinting) is applied before keying.

**Root cause / failed assumption:** The implementation assumes that clients will send canonical query strings. In reality, GraphQL comments (`# …`) are ignored tokens during parsing — two strings that differ only in their comments produce an identical parsed `Document`. The cache, however, treats them as entirely different keys.

**Exploit flow:**
1. Attacker sends `{ account { id } } # 1` → new cache entry (key = full string including `# 1`).
2. Attacker sends `{ account { id } } # 2` → new cache entry.
3. … repeated up to 1000 times.
4. Cache is now at `maximumSize=1000` (`CacheProperties.java` line 15). Caffeine's size-based eviction begins evicting entries — including legitimate cached queries from real users.
5. Attacker continues sending new unique-comment variants to keep the cache saturated.

**Why existing checks are insufficient:**

- `maxCharacters(10000)` (`GraphQlConfiguration.java` line 34): Limits each query to 10,000 characters, but a comment like `# 1` adds only 4 characters. An attacker has enormous headroom to generate unique variants.
- `maxWhitespaceTokens(1000)` (line 34): Limits ignored tokens *per query*, not across requests. The attack uses exactly one comment per request, so this limit is never triggered.
- `maximumSize=1000` (`CacheProperties.java` line 15): This is the attack surface, not a mitigation. It defines exactly how many junk entries are needed to saturate the cache.
- `expireAfterWrite=1h`: Entries persist for one hour. The attacker can re-saturate the cache every hour with a fresh batch of 1000 unique-comment queries.
- No authentication or rate-limiting is visible in the GraphQL configuration layer.

### Impact Explanation
Once the cache is saturated, every legitimate GraphQL request must re-parse and re-validate its query string from scratch on every invocation. This eliminates the performance benefit of the preparsed document cache entirely, increases CPU consumption proportionally to request volume, and raises response latency. Under sustained attack, this constitutes a targeted denial-of-service against the GraphQL endpoint's caching layer. Severity is **Medium** — the service remains functional but degrades measurably under load.

### Likelihood Explanation
The attack requires zero privileges — the GraphQL endpoint is publicly accessible. It is trivially automatable: a simple loop sending `query # N` for N in 1..1000 saturates the cache in a single burst. It is repeatable every hour as entries expire. No special knowledge of the application internals is required beyond knowing it is a GraphQL endpoint.

### Recommendation
Normalize the query string before using it as a cache key. The standard approach is to strip comments and collapse whitespace, or to use the AST's canonical printed form as the key:

```java
// Option 1: strip comments + normalize whitespace before caching
String normalizedQuery = normalizeQuery(executionInput.getQuery());
return cache.get(normalizedQuery, key -> parseAndValidateFunction.apply(executionInput));

// Option 2: parse once, use AST printer output as key (requires two-phase approach)
```

Alternatively, apply per-IP or per-client rate limiting at the ingress layer to bound the number of distinct query strings any single client can introduce into the cache within a time window.

### Proof of Concept
```python
import requests, threading

ENDPOINT = "https://<mirror-node-host>/graphql/alpha"
BASE_QUERY = "{ account(input: { entityId: { shard: 0, realm: 0, num: 2 } }) { id } }"

def flood(n):
    for i in range(n):
        payload = {"query": f"{BASE_QUERY} # {i}"}
        requests.post(ENDPOINT, json=payload)

# Step 1: saturate the 1000-slot cache with unique-comment variants
threads = [threading.Thread(target=flood, args=(100,)) for _ in range(10)]
for t in threads: t.start()
for t in threads: t.join()

# Step 2: send a legitimate query — it will NOT be served from cache
# (cache miss forces full parse+validate on every subsequent call)
r = requests.post(ENDPOINT, json={"query": BASE_QUERY})
print(r.json())  # served, but cache is now polluted; repeat to confirm cache miss rate
```

Repeating Step 2 in a loop while monitoring server-side cache hit metrics (exposed via `recordStats`) will show a near-zero hit rate, confirming cache exhaustion.