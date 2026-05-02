### Title
Unauthenticated `timestamp` Parameter Triggers Unbounded UNION Scan Against `entity_history` Table in `getContractById`

### Summary
Any unauthenticated external user can supply a `timestamp` query parameter to `GET /api/v1/contracts/{contractId}`, which unconditionally triggers a UNION query against the `entity_history` table. No lower-bound or reasonableness validation is applied to the timestamp value, so an attacker can supply an arbitrarily old timestamp (e.g., `timestamp=lte:1`) to force the database to evaluate the UNION branch on every request. Because the only row-limiting predicate in the history branch is the contract ID equality and the range-overlap condition, repeated requests constitute a low-cost, no-privilege-required amplification vector against the database.

### Finding Description

**Accepted parameter set** — `acceptedContractByIdParameters` is defined as:

```js
// rest/controllers/contractController.js line 1332
const acceptedContractByIdParameters = new Set([filterKeys.TIMESTAMP]);
```

`TIMESTAMP` is the *only* accepted query parameter for this endpoint, so any caller may supply it.

**Filter extraction** — `getContractById` (lines 707–737) calls `extractContractIdAndFiltersFromValidatedRequest` with that set, then immediately passes the resulting filters to `utils.extractTimestampRangeConditionFilters`:

```js
// lines 717-718
const {conditions: timestampConditions, params: timestampParams} =
  utils.extractTimestampRangeConditionFilters(filters);
```

`extractTimestampRangeConditionFilters` (utils.js lines 709–756) converts any timestamp filter into a PostgreSQL range value and a `&&` (overlap) condition. It performs **no validation of the timestamp value itself** — only format validation (seconds.nanoseconds) is done upstream by `filterValidityChecks`.

**UNION trigger** — `getContractByIdOrAddressContractEntityQuery` (lines 179–208) adds the `entity_history` UNION branch whenever `timestampConditions.length !== 0`:

```js
// lines 193-201
const tableUnionQueries = [getContractByIdOrAddressQueryForTable(Entity.tableName, conditions)];
if (timestampConditions.length !== 0) {
  tableUnionQueries.push(
    'union',
    getContractByIdOrAddressQueryForTable(Entity.historyTableName, conditions),
    `order by ${Entity.TIMESTAMP_RANGE} desc`,
    `limit 1`
  );
}
```

The generated SQL for the history branch is:

```sql
SELECT <fields>
FROM entity_history e
LEFT JOIN contract c ON e.id = c.id
WHERE e.type = 'CONTRACT'
  AND e.timestamp_range && $1   -- attacker-controlled range
  AND e.id = $2
ORDER BY e.timestamp_range DESC
LIMIT 1
```

**Why the existing checks are insufficient:**

- `filterValidityChecks` validates timestamp *format* (e.g., `0.000000001` is valid), not value range.
- `extractTimestampRangeConditionFilters` applies no floor/ceiling on the timestamp value.
- There is no guard that rejects a timestamp older than the network genesis or that skips the UNION when the supplied timestamp is provably before any entity was created.
- The `LIMIT 1` and `ORDER BY` apply only *after* both sides of the UNION are evaluated; they do not prevent the history-table scan.
- The only row-limiting predicate in the history branch is `e.id = $2`. If `entity_history` lacks a covering index on `(id, timestamp_range)`, the database must scan all history rows for that contract ID and evaluate the range overlap for each.

### Impact Explanation
An attacker can force the mirror-node REST API to execute the more expensive two-table UNION path on every `GET /api/v1/contracts/{contractId}` request simply by appending `?timestamp=lte:1`. With a timestamp of `1` nanosecond, the range condition `e.timestamp_range && (-∞, 1]` matches nothing on a live network, but the database still plans and executes the full UNION branch. Repeated at high rate (no authentication, no per-IP rate limit enforced at the application layer), this degrades database performance for all consumers of the mirror node. Severity: **Medium** (availability impact, no data exfiltration).

### Likelihood Explanation
- Zero privileges required; the endpoint is public.
- The exploit is a single HTTP GET with one query parameter.
- Fully automatable; a simple loop or off-the-shelf HTTP flood tool suffices.
- The attacker needs only a valid contract ID (trivially obtained from the `/api/v1/contracts` listing endpoint).

### Recommendation
1. **Add a minimum timestamp guard**: before calling `getContractByIdOrAddressContractEntityQuery`, reject or ignore timestamp values that are provably before the network genesis timestamp.
2. **Skip the UNION when the timestamp range cannot overlap any history record**: if the supplied timestamp is older than the earliest known `entity_history` record, return `NotFoundError` immediately.
3. **Alternatively, require a timestamp lower bound**: reject open-ended `lte`/`lt`/`eq` timestamp filters that have no corresponding `gte`/`gt` lower bound, consistent with the range-validation logic already present in `parseTimestampFilters`.
4. **Ensure a covering index** on `entity_history(id, timestamp_range)` so that even when the UNION branch executes, it uses an index seek rather than a sequential scan.

### Proof of Concept

```
# Step 1 – obtain any valid contract ID (no auth required)
GET /api/v1/contracts?limit=1
# → returns e.g. contractId = "0.0.1234"

# Step 2 – trigger the entity_history UNION with an arbitrarily old timestamp
GET /api/v1/contracts/0.0.1234?timestamp=lte:1

# Step 3 – repeat at high rate to amplify database load
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/contracts/0.0.1234?timestamp=lte:1" &
done
```

Each request causes the mirror node to execute:
```sql
SELECT ... FROM entity e ... WHERE e.type='CONTRACT' AND e.timestamp_range && '(,1]' AND e.id=1234
UNION
SELECT ... FROM entity_history e ... WHERE e.type='CONTRACT' AND e.timestamp_range && '(,1]' AND e.id=1234
ORDER BY e.timestamp_range DESC LIMIT 1
```
with no authentication and no server-side guard preventing the history-table branch from being evaluated. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/controllers/contractController.js (L193-201)
```javascript
  const tableUnionQueries = [getContractByIdOrAddressQueryForTable(Entity.tableName, conditions)];
  if (timestampConditions.length !== 0) {
    // if there is timestamp condition, union the result from both tables
    tableUnionQueries.push(
      'union',
      getContractByIdOrAddressQueryForTable(Entity.historyTableName, conditions),
      `order by ${Entity.TIMESTAMP_RANGE} desc`,
      `limit 1`
    );
```

**File:** rest/controllers/contractController.js (L707-724)
```javascript
  getContractById = async (req, res) => {
    if (utils.conflictingPathParam(req, 'contractId', 'results')) {
      return;
    }

    const {filters, contractId: contractIdParam} = extractContractIdAndFiltersFromValidatedRequest(
      req,
      acceptedContractByIdParameters
    );

    const {conditions: timestampConditions, params: timestampParams} =
      utils.extractTimestampRangeConditionFilters(filters);

    const {query, params} = getContractByIdOrAddressContractEntityQuery({
      timestampConditions,
      timestampParams,
      contractIdParam,
    });
```

**File:** rest/controllers/contractController.js (L1332-1332)
```javascript
const acceptedContractByIdParameters = new Set([filterKeys.TIMESTAMP]);
```

**File:** rest/utils.js (L709-756)
```javascript
const extractTimestampRangeConditionFilters = (
  filters,
  offset = 0,
  timestampRangeColumn = Entity.getFullName(Entity.TIMESTAMP_RANGE)
) => {
  const conditions = [];
  const params = [];

  filters
    .filter((filter) => filter.key === constants.filterKeys.TIMESTAMP)
    .forEach((filter) => {
      const position = `$${params.length + offset + 1}`;
      let condition;
      let range;

      if (filter.operator === opsMap.ne) {
        // handle ne filter differently
        condition = `not ${timestampRangeColumn} @> ${position}`; // @> is the pg range "contains" operator
        range = Range(filter.value, filter.value, '[]');
      } else {
        condition = `${timestampRangeColumn} && ${position}`; // && is the pg range "overlaps" operator

        switch (filter.operator) {
          case opsMap.lt:
            range = Range(null, filter.value, '()');
            break;
          case opsMap.eq:
          case opsMap.lte:
            range = Range(null, filter.value, '(]');
            break;
          case opsMap.gt:
            range = Range(filter.value, null, '()');
            break;
          case opsMap.gte:
            range = Range(filter.value, null, '[)');
            break;
        }
      }

      conditions.push(condition);
      params.push(range);
    });

  return {
    conditions,
    params,
  };
};
```
