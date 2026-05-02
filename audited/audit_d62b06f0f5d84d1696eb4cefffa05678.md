### Title
Unbounded `string_agg` Aggregation via User-Controlled Timestamp Anchor in `getFileDataQuery`

### Summary
The `getFileData()` function in `rest/service/fileDataService.js` passes a user-supplied `timestamp` directly as `$2` into `getFileDataQuery`. The correlated subquery selects the most recent FileCreate (type 17) or non-empty FileUpdate (type 19) with `consensus_timestamp <= $2` as the aggregation anchor. By supplying a timestamp just before a recent FileCreate/FileUpdate, an unprivileged attacker forces the anchor to resolve to a much earlier FileCreate, causing the outer `string_agg` to consume all `file_data` rows between that old anchor and `$2` — with no row count or byte-size cap.

### Finding Description

**Code path:**

`rest/service/fileDataService.js`, lines 44–76:

```js
static getFileDataQuery = `select
     string_agg(file_data, '' order by consensus_timestamp) data
    from file_data
    where
       entity_id = $1
    and consensus_timestamp >= (
    select consensus_timestamp
    from file_data
    where entity_id = $1
    and consensus_timestamp <= $2          -- user-controlled upper bound
    and (transaction_type = 17
         or ( transaction_type = 19
              and length(file_data) <> 0 ))
    order by consensus_timestamp desc
    limit 1
    ) and consensus_timestamp <= $2`;      -- outer query: NO row/byte limit

getFileData = async (fileId, timestamp) => {
  const params = [fileId, timestamp];     // timestamp is caller-supplied
  const query = FileDataService.getFileDataQuery;
  const row = await super.getSingleRow(query, params);
  return row === null ? null : row.data;
};
```

**Root cause:** The outer `string_agg` has no `LIMIT`, no `max_length` guard, and no transaction-type filter. The anchor returned by the subquery is entirely determined by `$2`. The failed assumption is that `$2` will always be near the present, so the anchor will always be recent. In reality, a caller can supply any syntactically valid timestamp.

**Exploit flow:**

Suppose a file has the following history:
- `T=100` — FileCreate (initial, 1 MB)
- `T=101…999` — 899 × FileAppend (each 1 MB → 899 MB total)
- `T=1000` — FileUpdate with content (resets file to 1 byte)
- No further rows

| Request `$2` | Subquery anchor | Rows aggregated | Bytes |
|---|---|---|---|
| `1000` (normal) | T=1000 | 1 | ~1 B |
| `999` (attack) | T=100 | 900 | ~900 MB |

By choosing `$2 = 999`, the attacker shifts the anchor from T=1000 to T=100, forcing the DB to `string_agg` 900 rows totalling ~900 MB in a single query — a >30% resource spike achievable with a single HTTP request, repeatable at will.

**Why existing checks are insufficient:**

The only validation applied to the timestamp before it reaches `getFileData` is a format check (`utils.isValidTimestampParam` / `utils.parseTimestampParam` in `contractController.js`, lines 356–370). This confirms the value matches `seconds.nanoseconds` syntax but imposes no semantic bound (e.g., no "must not be before the most recent FileCreate"). There is no rate-limit, no per-query byte cap, and no `LIMIT` clause on the outer aggregation.

### Impact Explanation
A single crafted request can force PostgreSQL to materialise and concatenate hundreds of megabytes (or gigabytes, for long-lived system files such as the address-book or fee-schedule) into a single `string_agg` result. This exhausts DB working memory, spills to disk, and saturates the REST node's network egress. Because the attack is stateless and requires no authentication, it can be issued in parallel from multiple clients, sustaining elevated resource consumption indefinitely. Severity: **High** (DoS against a public, unauthenticated API endpoint).

### Likelihood Explanation
The attack requires only:
1. Knowledge of a `fileId` whose historical data is large (system file IDs such as `0.0.101`, `0.0.102`, `0.0.111`, `0.0.112` are publicly documented).
2. Knowledge of the approximate timestamp of the most recent FileCreate/FileUpdate for that file (obtainable from the mirror-node's own transaction history API).
3. A single HTTP GET request with a crafted `consensusTimestamp` path parameter.

No credentials, no special network position, and no brute-force are required. The attack is fully repeatable.

### Recommendation
1. **Add a lower-bound parameter to the subquery** (as the `rest-java` variant already does — `consensus_timestamp >= ?2 AND consensus_timestamp <= ?3`) so the anchor search is confined to a caller-supplied or server-enforced window.
2. **Enforce a maximum aggregation window** (e.g., reject or cap requests where `$2 − anchor > N nanoseconds`).
3. **Add a `LIMIT` or `max_length` guard** on the `string_agg` call, or stream results rather than materialising the entire concatenation in memory.
4. **Apply rate-limiting** on the endpoint that invokes `getFileData`.

### Proof of Concept

```
# 1. Discover the timestamp of the most recent FileUpdate for file 0.0.112
GET /api/v1/transactions?transactiontype=FILEUPDATE&account.id=0.0.112&order=desc&limit=1

# Note the consensus_timestamp T_update from the response.

# 2. Compute T_attack = T_update - 1 nanosecond (expressed as seconds.nanos)

# 3. Issue the crafted request (replace <contractId> with any contract whose
#    file_id resolves to 0.0.112, or use the direct fileData service path)
GET /api/v1/contracts/<contractId>/results/<T_attack>

# The DB will now execute getFileDataQuery with $2 = T_attack,
# the subquery will anchor at the original FileCreate of 0.0.112 (potentially
# years in the past), and string_agg will concatenate every file_data row
# from that creation to T_attack — potentially hundreds of MB — in one query.

# 4. Repeat in a tight loop from multiple clients to sustain >30% resource elevation.
```