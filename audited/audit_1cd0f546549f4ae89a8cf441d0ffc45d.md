### Title
Anchor-Skip via Empty FILEUPDATE Causes `getFileDataQuery` to Return Stale File Content

### Summary
The `getFileDataQuery` subquery in `rest/service/fileDataService.js` intentionally excludes FILEUPDATE (type=19) rows with empty `file_data` from anchor selection via the `length(file_data) <> 0` guard. When a legitimate FILEUPDATE that clears a file to empty content exists in the database, an unprivileged caller can supply a `$2` timestamp value just after that empty FILEUPDATE, causing the subquery to skip it and anchor on an earlier FILECREATE (type=17). The outer `string_agg` then concatenates all rows from that stale anchor forward, returning pre-update content instead of the correct empty state.

### Finding Description

**Exact code path:** `rest/service/fileDataService.js`, static property `getFileDataQuery`, lines 43–62. [1](#0-0) 

The subquery (lines 51–62) selects the most recent "anchor" row with `consensus_timestamp <= $2`:

```sql
select consensus_timestamp
from file_data
where entity_id = $1
  and consensus_timestamp <= $2
  and (transaction_type = 17
       or ( transaction_type = 19
            and length(file_data) <> 0 ))   -- ← problematic guard
order by consensus_timestamp desc
limit 1
``` [2](#0-1) 

**Root cause:** The guard `length(file_data) <> 0` was added to avoid treating a no-op FILEUPDATE as an anchor, but it also silently skips a *legitimate* FILEUPDATE that sets the file to empty content. The failed assumption is that every FILEUPDATE with empty `file_data` is a metadata-only no-op; in reality it can be a valid content-clearing operation.

**Exploit flow:**

Given the following database state for a file:

| consensus_timestamp | transaction_type | file_data |
|---|---|---|
| T1 | 17 (FILECREATE) | `<original content>` |
| T2 | 16 (FILEAPPEND) | `<appended chunk>` |
| T3 | 19 (FILEUPDATE) | `""` (empty — file cleared) |
| T4 | 16 (FILEAPPEND) | `<new chunk>` |

An attacker supplies `$2 = T3 + 1` (any value in the range `(T3, T4)`):

1. Subquery evaluates candidates with `consensus_timestamp <= T3+1`.
2. The FILEUPDATE at T3 has `length(file_data) = 0`, so it is **excluded**.
3. The next candidate is the FILECREATE at T1 — this becomes the anchor.
4. The outer query aggregates all rows of types 16/17/19 from T1 to T3+1, producing `<original content> || <appended chunk> || ""` — the stale pre-update content.
5. The correct answer for the file state at T3+1 is empty (`""`).

**Why existing checks fail:** The only guard against this is the `length(file_data) <> 0` condition, which is precisely the mechanism that *causes* the skip. There is no secondary validation that the returned content is consistent with the most recent FILEUPDATE in the queried range.

### Impact Explanation

The query is used to reconstruct historical file contents for Hedera system files (exchange rates, fee schedules, address books) and user files via the REST API (`getFileData`, called from `contractController.js`). Returning stale content for a timestamp at which the file was actually empty misrepresents the authoritative on-chain state. For system files such as the exchange rate file (`EntityId.systemEntity.exchangeRateFile`), this could be used to assert a different rate was in effect at a given time, enabling disputes or off-chain manipulation of settlement logic that relies on mirror-node data. Severity: **Medium** — no direct fund movement, but authoritative data integrity is compromised. [3](#0-2) 

### Likelihood Explanation

The precondition — a FILEUPDATE with empty `file_data` in the database — is a valid on-chain operation any file owner can perform. Once such a row exists (observable via public blockchain explorers), any unauthenticated caller of the REST API can supply a crafted `$2` timestamp. The attack is deterministic, requires no special privileges, and is repeatable as long as the row exists. Likelihood: **Low-Medium** (depends on whether empty FILEUPDATEs exist for targeted files; trivially achievable for attacker-owned files, less common for system files).

### Recommendation

Remove the `length(file_data) <> 0` guard from the anchor-selection subquery, or replace it with explicit logic that treats an empty FILEUPDATE as a valid anchor (resetting the content to empty). The corrected subquery should be:

```sql
and (transaction_type = 17 or transaction_type = 19)
```

If the intent is to skip FILEUPDATEs that carry no content change (metadata-only), that distinction must be encoded in a separate column (e.g., a boolean `content_changed` flag), not inferred from `length(file_data)`. Additionally, add a post-query consistency check: if the most recent type=19 row in the result window has empty `file_data`, the aggregated result should be empty regardless of earlier rows.

### Proof of Concept

```sql
-- Setup: insert a file with a clearing FILEUPDATE
INSERT INTO file_data VALUES (1, 'entity_1', 17, '\xDEADBEEF');  -- T=1 FILECREATE
INSERT INTO file_data VALUES (2, 'entity_1', 16, '\xCAFEBABE');  -- T=2 FILEAPPEND
INSERT INTO file_data VALUES (3, 'entity_1', 19, '');            -- T=3 FILEUPDATE (clears file)
INSERT INTO file_data VALUES (4, 'entity_1', 16, '\x11223344');  -- T=4 FILEAPPEND

-- Attacker calls REST API with timestamp $2 = 3 (or any value in (3,4))
-- Expected result: empty string (file was cleared at T=3)
-- Actual result:   '\xDEADBEEF\xCAFEBABE' (stale pre-update content)

-- Reproduce directly:
SELECT string_agg(file_data, '' ORDER BY consensus_timestamp)
FROM file_data
WHERE entity_id = 'entity_1'
  AND consensus_timestamp >= (
    SELECT consensus_timestamp FROM file_data
    WHERE entity_id = 'entity_1'
      AND consensus_timestamp <= 3
      AND (transaction_type = 17
           OR (transaction_type = 19 AND length(file_data) <> 0))
    ORDER BY consensus_timestamp DESC LIMIT 1
  )
  AND consensus_timestamp <= 3;
-- Returns: '\xDEADBEEF\xCAFEBABE'  ← WRONG, should be empty
```

### Citations

**File:** rest/service/fileDataService.js (L43-62)
```javascript
  static getFileDataQuery = `select
         string_agg(
           ${FileData.FILE_DATA}, ''
           order by ${FileData.CONSENSUS_TIMESTAMP}
           ) data
        from ${FileData.tableName}
        where
           ${FileData.ENTITY_ID} = $1
        and ${FileData.CONSENSUS_TIMESTAMP} >= (
        select ${FileData.CONSENSUS_TIMESTAMP}
        from ${FileData.tableName}
        where ${FileData.ENTITY_ID} = $1
        and ${FileData.CONSENSUS_TIMESTAMP} <= $2
        and (${FileData.TRANSACTION_TYPE} = 17
             or ( ${FileData.TRANSACTION_TYPE} = 19
                  and
                  length(${FileData.FILE_DATA}) <> 0 ))
        order by ${FileData.CONSENSUS_TIMESTAMP} desc
        limit 1
        ) and ${FileData.CONSENSUS_TIMESTAMP} <= $2`;
```

**File:** rest/service/fileDataService.js (L70-75)
```javascript
  getFileData = async (fileId, timestamp) => {
    const params = [fileId, timestamp];
    const query = FileDataService.getFileDataQuery;
    const row = await super.getSingleRow(query, params);
    return row === null ? null : row.data;
  };
```
