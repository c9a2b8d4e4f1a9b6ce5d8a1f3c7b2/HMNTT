### Title
Unauthenticated DB Connection Pool Exhaustion via Combined `sequencenumber`+`timestamp` Filters When `topicMessageLookup` Is Enabled

### Summary
When `hiero.mirror.rest.query.topicMessageLookup` is enabled, any unauthenticated user can send requests to `GET /api/v1/topics/:topicId/messages` with both `sequencenumber` and `timestamp` query parameters simultaneously. This unconditionally triggers the expensive two-query CTE path in `getTopicMessageTimestampRanges()`, holding DB connections for up to the 20-second statement timeout. With a default pool of only 10 connections and no rate limiting on the REST API, a modest number of concurrent requests exhausts the pool, rendering the REST API unavailable.

### Finding Description

**Exact code path:**

In `rest/topicmessage.js`, `getTopicMessages()` (line 116) calls `extractSqlFromTopicMessagesRequest()` (line 162). When `topicMessageLookupEnabled` is true, every filter of type `SEQUENCE_NUMBER` or `TIMESTAMP` is pushed into `sequenceNumberFilters` and `timestampFilters` respectively (lines 191–193). Both arrays are then unconditionally passed to `getTopicMessageTimestampRanges()` (line 200).

Inside `getTopicMessageTimestampRanges()` (line 254), the branch at line 269 decides which query to run:

```js
if (sequenceNumberRange.upper - sequenceNumberRange.lower + 1n <= limit) {
  // simple single query
} else {
  // expensive CTE: two DB queries
}
```

An attacker sends `?sequencenumber=gte:1&timestamp=lte:9999999999.999999999`. This produces:
- `sequenceNumberRange = {lower: 1n, upper: MAX_LONG-1n}` — a range of ~9.2×10¹⁸
- `timestampRange = {lower: 0n, upper: <parsed value>}`

Since `MAX_LONG-1n - 1n + 1n` vastly exceeds any limit (max 100), the expensive CTE path (lines 295–312) always executes. This path issues **two sequential DB queries** (a `LIMIT 1` subquery + a join), followed by the main `topic_message` query — **3 total DB queries per request**, each held for up to `statementTimeout = 20000ms`.

**Root cause:** No rate limiting exists on the Node.js REST API for this endpoint. The expensive path is triggered by any valid combination of both filter types with a wide sequence number range, which is always the case when no upper bound on `sequencenumber` is provided.

**Why existing checks fail:**
- `maxRepeatedQueryParameters = 100` limits filter repetition but a single `sequencenumber=gte:1` is sufficient to trigger the expensive path.
- `statementTimeout = 20000ms` bounds individual query duration but does not prevent pool exhaustion — 10 concurrent requests each holding a connection for 20s saturates the default pool of `maxConnections = 10`.
- `getRangeFromFilters()` returns `null` only for contradictory/empty ranges; a wide valid range passes through.
- The `topicMessageLookup` feature has no associated rate limiting or concurrency guard.

### Impact Explanation

The REST API DB pool (`maxConnections = 10` by default) is exhausted by ~10 concurrent crafted requests. Subsequent requests receive connection timeout errors (`connectionTimeoutMillis = 20000ms`), making the entire mirror node REST API unavailable for the duration of the attack. This is a sustained, low-bandwidth DoS. Note: the mirror node is a read-only service and does not participate in Hedera consensus — this does not cause "total network shutdown" but does cause complete REST API unavailability, which disrupts all downstream consumers (wallets, explorers, dApps) relying on the mirror node.

### Likelihood Explanation

- **Precondition**: `topicMessageLookup` must be explicitly enabled (non-default: `false`). Operators enabling this feature for production use are the target.
- **No authentication required**: The endpoint is fully public.
- **Trivial to exploit**: A single `curl` loop or any HTTP load tool suffices.
- **Repeatable**: The attack sustains as long as requests keep arriving; no special knowledge of the topic data is needed.
- **Low bandwidth**: Each request is a small GET with two query parameters.

### Recommendation

1. **Add rate limiting to the REST API** for the `/topics/:topicId/messages` endpoint, particularly when `topicMessageLookup` is enabled. The web3 module's `ThrottleManager` pattern (bucket4j) can serve as a model.
2. **Add a concurrency guard** in `getTopicMessageTimestampRanges()` to limit simultaneous in-flight expensive CTE queries (e.g., a semaphore).
3. **Increase `maxConnections`** or reduce `statementTimeout` when `topicMessageLookup` is enabled to limit blast radius.
4. **Require a bounded `sequencenumber` range** (both lower and upper bounds) when `topicMessageLookup` is enabled, rejecting open-ended ranges that unconditionally trigger the expensive path.

### Proof of Concept

```bash
# Trigger the expensive CTE path with a wide sequence number range + timestamp filter
# Run 15 concurrent requests to exhaust the default pool of 10 connections

for i in $(seq 1 15); do
  curl -s "http://<mirror-node-host>:5551/api/v1/topics/1/messages?sequencenumber=gte:1&timestamp=lte:9999999999.999999999" &
done
wait

# Subsequent requests will receive connection timeout errors:
curl -v "http://<mirror-node-host>:5551/api/v1/topics/1/messages"
# Expected: connection timeout / 503 after connectionTimeoutMillis (20s)
```

**Relevant lines:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/topicmessage.js (L191-200)
```javascript
        if (topicMessageLookupEnabled) {
          filtersMap[filter.key].push(filter);
        }
        conditions.push(`${column}${filter.operator}$${params.push(filter.value)}`);
        break;
    }
  }

  if (topicMessageLookupEnabled) {
    const ranges = await getTopicMessageTimestampRanges(topicId, sequenceNumberFilters, timestampFilters, limit, order);
```

**File:** rest/topicmessage.js (L269-312)
```javascript
  if (sequenceNumberRange.upper - sequenceNumberRange.lower + 1n <= limit) {
    // If the range size doesn't exceed the limit, use it as is. Note explicitly casting topic id to bigint is
    // required to utilize the btree gist index on (topic_id, sequence_number_range)
    query = `select timestamp_range
      from topic_message_lookup
      where topic_id = $1::bigint and sequence_number_range && $2::int8range and timestamp_range && $3::int8range
      order by sequence_number_range`;
  } else {
    // Depending on the order, first query the table to find the bound of the sequence number range and build the actual
    // range from the bound and the limit, then query the table with the actual range
    params.push(limit);
    // Since the information in the table can't tell the first sequence number satisfying the sequence number range and
    // the timestamp range, for instance, with sequencenumber=lt:500, timestamp=lt:1000, limit=25, and order=desc, the
    // first sequence number range might be [300, 400), the minimum value of the largest sequence number is 300, and
    // the maximum is 399. In order to get the correct timestamp range, we need to use an actual range which covers
    // all possible sequence number values, i.e., [276, 400)
    // Notes:
    // - for asc order, when expanding the upper, the delta least(limit, 9223372036854775807::bigint - upper(range)) is
    //   used to ensure no overflow occurs
    // - for desc order, lower bound is expanded by limit - 1, since the lower bound is inclusive
    // - upper($2::int8range) is always the exclusive upper bound, i.e., when the value passed in is '[1, 10]', pg
    //   upper returns 11
    const rangeExpression = isOrderAsc
      ? `int8range(lower(range), least(upper(range) + least($4, 9223372036854775807::bigint - upper(range)), upper($2::int8range)), '[)')`
      : `int8range(greatest(lower(range) - ($4 - 1), lower($2::int8range)), upper(range), '[)')`;

    query = `with actual_range as (
        select ${rangeExpression} as range
        from (
          select sequence_number_range as range
          from topic_message_lookup
          where topic_id = $1::bigint and
            sequence_number_range && $2::int8range and
            timestamp_range && $3::int8range
          order by sequence_number_range ${order}
          limit 1
        ) as t
      )
      select timestamp_range
      from topic_message_lookup as t, actual_range as a
      where topic_id = $1::bigint and
        sequence_number_range && a.range and
        timestamp_range && $3::int8range
      order by sequence_number_range`;
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```
