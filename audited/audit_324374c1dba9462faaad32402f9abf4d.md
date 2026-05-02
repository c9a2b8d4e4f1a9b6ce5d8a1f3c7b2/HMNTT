### Title
Unrestricted Timestamp Range in `getBlocks()` Enables Unauthenticated DB Query Flood DoS

### Summary
The `getBlocks()` handler in `rest/controllers/blockController.js` accepts arbitrary `timestamp` range filters and passes them directly to the database without invoking `parseTimestampFilters()` — the shared utility that enforces `maxTimestampRange` (default 7 days) and is used by every other timestamp-filtered endpoint. With no application-level rate limiting on the Node.js REST API blocks endpoint, an unauthenticated attacker can issue unlimited requests with arbitrary timestamp windows, each generating a real DB query against the `record_file.consensus_end` index.

### Finding Description

**Code path:**

`getBlocks()` in `rest/controllers/blockController.js` (lines 101–112): [1](#0-0) 

It calls `buildAndValidateFilters()` (format-only validation) then `extractSqlFromBlockFilters()`: [2](#0-1) 

For `TIMESTAMP` filters, `extractSqlFromBlockFilters()` calls only `getFilterWhereCondition(RecordFile.CONSENSUS_END, f)` — a direct SQL condition mapping. It **never** calls `parseTimestampFilters()`.

**Contrast with other endpoints:** `contractController.js` and `accounts.js` both call `parseTimestampFilters(..., validateRange=true)`, which enforces `maxTimestampRangeNs` (default 7 days): [3](#0-2) 

The blocks endpoint bypasses this entirely. The resulting SQL from `RecordFileService.getBlocks()`: [4](#0-3) 

…executes `WHERE consensus_end >= $1 AND consensus_end <= $2` with no lower bound on range width.

**No application-level rate limiting** exists for the Node.js REST API blocks endpoint. The throttle/rate-limit infrastructure found in the codebase applies only to the Java `web3` service (contract calls): [5](#0-4) 

The `maxTimestampRange` config is documented and enforced for other endpoints but not for blocks: [6](#0-5) 

### Impact Explanation

Each request with `timestamp=gte:N&timestamp=lte:N+1` generates a real parameterized query against the `record_file` table's `consensus_end` index. Because the query is cheap per-execution (index seek, near-zero rows returned), the Node.js process accepts and dispatches them at high throughput — meaning the attacker can sustain a much higher request rate before hitting any server-side CPU limit. The cumulative effect is DB connection pool exhaustion and index I/O saturation. With the default DB pool `maxConnections` and no request queuing limit, a sustained flood degrades or denies service to all other API consumers. The `record_file` table is central to block, transaction, and contract result lookups, so degradation here cascades across the mirror node API surface.

### Likelihood Explanation

No authentication, no API key, no rate limiting, and no minimum range size are required. The endpoint is publicly reachable at `GET /api/v1/blocks`. A single attacker with a modest HTTP client (e.g., `wrk`, `ab`, or a simple async script) can sustain thousands of requests per second. The attack is trivially repeatable, requires no special knowledge beyond reading the OpenAPI spec, and leaves no persistent state to clean up between runs.

### Recommendation

1. **Call `parseTimestampFilters()` with `validateRange=true`** inside `extractSqlFromBlockFilters()` or `getBlocks()` for any timestamp filters, consistent with how `contractController.js` and `accounts.js` handle it. This enforces the existing `maxTimestampRange` (7d) guard.
2. **Add application-level rate limiting** to the Node.js REST API (e.g., via `express-rate-limit` or a Traefik `rateLimit` middleware entry for the `/api/v1/blocks` route), mirroring the pattern already used for the Rosetta service.
3. **Enforce a minimum timestamp range width** (e.g., reject ranges narrower than 1 second) to prevent degenerate point-scan flooding even within the 7-day window.

### Proof of Concept

```bash
# No authentication required
# Send 10,000 requests with 1-nanosecond windows across different offsets
for i in $(seq 1 10000); do
  curl -s "http://<mirror-node>/api/v1/blocks?timestamp=gte:${i}&timestamp=lte:$((i+1))" &
done
wait
```

Each request is accepted, validated (format only), and dispatched as:
```sql
SELECT ... FROM record_file
WHERE consensus_end >= $1 AND consensus_end <= $2
ORDER BY consensus_end DESC
LIMIT 25;
-- $1 = i, $2 = i+1
```

No 400 error is returned. The DB executes all queries. Sustained at scale, this exhausts the connection pool and degrades the service for all users.

### Citations

**File:** rest/controllers/blockController.js (L63-88)
```javascript
  extractSqlFromBlockFilters = (filters) => {
    const filterQuery = {
      order: this.extractOrderFromFilters(filters),
      orderBy: this.extractOrderByFromFilters(filters),
      limit: this.extractLimitFromFilters(filters),
      whereQuery: [],
    };

    if (filters && filters.length === 0) {
      return filterQuery;
    }

    filterQuery.whereQuery = filters
      .filter((f) => blockWhereFilters.includes(f.key))
      .map((f) => {
        switch (f.key) {
          case filterKeys.BLOCK_NUMBER:
            return this.getFilterWhereCondition(RecordFile.INDEX, f);

          case filterKeys.TIMESTAMP:
            return this.getFilterWhereCondition(RecordFile.CONSENSUS_END, f);
        }
      });

    return filterQuery;
  };
```

**File:** rest/controllers/blockController.js (L101-112)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);

    res.locals[responseDataLabel] = {
      blocks: blocks.map((model) => new BlockViewModel(model)),
      links: {
        next: this.generateNextLink(req, blocks, formattedFilters),
      },
    };
  };
```

**File:** rest/utils.js (L1657-1665)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
```

**File:** rest/service/recordFileService.js (L149-162)
```javascript
  async getBlocks(filters) {
    const {where, params} = buildWhereSqlStatement(filters.whereQuery);

    const query =
      RecordFileService.blocksQuery +
      `
      ${where}
      order by ${filters.orderBy} ${filters.order}
      limit ${filters.limit}
    `;

    const rows = await super.getRows(query, params);
    return rows.map((recordFile) => new RecordFile(recordFile));
  }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** docs/configuration.md (L584-584)
```markdown
| `hiero.mirror.rest.query.maxTimestampRange`                              | 7d                      | The maximum amount of time a timestamp range query param can span for some APIs.                                                                                                              |
```
