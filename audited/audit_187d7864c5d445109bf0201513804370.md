Based on my investigation of the code and database schema, here is my analysis:

**Code examined:**
- `rest/schedules.js` — `extractSqlFromScheduleFilters()` (lines 154–204), `getSchedules()` (lines 234–282)
- `importer/src/main/resources/db/migration/v2/V2.0.3__index_init.sql` (lines 197–201)
- `importer/src/main/resources/db/migration/v1/V1.35.2__schedule_index.sql`
- `importer/src/main/resources/db/migration/v1/V1.42.0__schedule_primary_key.sql`

**Indexes confirmed on `schedule` table:**
- Primary key on `schedule_id` (single column)
- `schedule__creator_account_id` on `creator_account_id desc` (single column)
- **No composite index on `(creator_account_id, schedule_id)`**

---

### Title
Missing Composite Index Enables Full-Table-Scan DoS via Combined `account.id` + `schedule.id` Filters on `/api/v1/schedules`

### Summary
`getSchedules()` delegates filter construction to `extractSqlFromScheduleFilters()`, which freely combines `creator_account_id` and `s.schedule_id` predicates into a single WHERE clause. Because no composite index on `(creator_account_id, schedule_id)` exists, PostgreSQL is forced to use the primary-key index for `ORDER BY s.schedule_id` and apply `creator_account_id` as a post-filter, causing a full sequential scan of the table when the `creator_account_id` predicate matches zero rows. An unauthenticated attacker can exploit this with concurrent requests to saturate database I/O.

### Finding Description

**Exact code path:**

`getSchedules()` calls `buildAndValidateFilters` then `extractSqlFromScheduleFilters`:

```js
// rest/schedules.js lines 154-204
const extractSqlFromScheduleFilters = (filters) => {
  ...
  whereQuery += `${filterColumnMap[filter.key]}${filter.operator}$${paramCount}`;
  ...
};
``` [1](#0-0) 

When both `account.id` and `schedule.id` are supplied, the generated query is:

```sql
select ... from schedule s
where creator_account_id >= $1 and s.schedule_id < $2
order by s.schedule_id ASC
limit $3
``` [2](#0-1) 

**Root cause — missing composite index:**

The only indexes on `schedule` are:
- Primary key on `schedule_id` (used for `ORDER BY`)
- Single-column index on `creator_account_id desc` [3](#0-2) 

Because `ORDER BY s.schedule_id ASC` forces the planner to use the primary-key index for ordering, the `creator_account_id >= $1` predicate cannot use its own index and becomes a row-by-row post-filter. When `$1` is set to a value that matches zero rows (e.g., a very high account ID), PostgreSQL must scan every row in the table before returning an empty result set — the `LIMIT` clause provides no early-exit benefit when 0 rows satisfy the filter.

**Why the LIMIT does not help:**

`LIMIT N` only stops the scan early when N rows have already been *returned*. If the `creator_account_id` predicate eliminates every row, the engine scans the entire table and returns 0 rows regardless of the limit value. [4](#0-3) 

**No rate limiting or authentication found** on this endpoint — it is publicly accessible per the OpenAPI spec: [5](#0-4) 

### Impact Explanation

An unauthenticated attacker sending concurrent requests such as:

```
GET /api/v1/schedules?account.id=gte:0.0.999999999&schedule.id=lt:999999999
```

forces repeated full-table scans on the `schedule` table. Under concurrent load this saturates database I/O and CPU, degrading or denying service to the mirror node REST API. This affects all mirror node consumers (wallets, explorers, dApps). Note: this impacts mirror node availability, not Hedera network consensus directly.

### Likelihood Explanation

- **No authentication required** — any external user can trigger this.
- **No rate limiting** found in the examined code paths.
- **Trivially repeatable** — a simple script sending concurrent HTTP GET requests is sufficient.
- The attacker needs zero privileges and zero knowledge of the system beyond the public API spec.

### Recommendation

1. **Add a composite index** on `(creator_account_id, schedule_id)` so the planner can satisfy both the filter and the ordering from a single index scan:
   ```sql
   create index if not exists schedule__creator_account_id_schedule_id
       on schedule (creator_account_id, schedule_id);
   ```
2. **Implement rate limiting** on the `/api/v1/schedules` endpoint (e.g., via an API gateway or Express middleware).
3. **Reject or short-circuit** queries where the `creator_account_id` filter is known to be non-selective (e.g., `gte:0` covering the entire table) when combined with a `schedule_id` range filter.

### Proof of Concept

```bash
# Single request demonstrating the worst-case query
curl "https://<mirror-node>/api/v1/schedules?account.id=gte:0.0.999999999&schedule.id=lt:999999999"

# Concurrent flood to saturate DB I/O
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/schedules?account.id=gte:0.0.999999999&schedule.id=lt:999999999" &
done
wait
```

The generated SQL (`WHERE creator_account_id >= <high_value> AND s.schedule_id < <large_value> ORDER BY s.schedule_id ASC LIMIT 25`) will perform a full sequential scan of the `schedule` table on each request, returning 0 rows only after scanning every row. Under concurrent load this exhausts DB I/O capacity.

### Citations

**File:** rest/schedules.js (L67-68)
```javascript
const scheduleLimitQuery = (paramCount) => `limit $${paramCount}`;
const scheduleOrderQuery = (order) => `order by s.schedule_id ${order}`;
```

**File:** rest/schedules.js (L77-79)
```javascript
const getSchedulesQuery = (whereQuery, order, count) => {
  return [schedulesMainQuery, whereQuery, scheduleOrderQuery(order), scheduleLimitQuery(count)].join('\n');
};
```

**File:** rest/schedules.js (L154-204)
```javascript
const extractSqlFromScheduleFilters = (filters) => {
  const filterQuery = {
    filterQuery: '',
    params: [defaultLimit],
    order: constants.orderFilterValues.ASC,
    limit: defaultLimit,
  };

  // if no filters return default filter of no where clause, defaultLimit and asc order
  if (filters && filters.length === 0) {
    return filterQuery;
  }

  const pgSqlParams = [];
  let whereQuery = '';
  let applicableFilters = 0; // track the number of schedule specific filters
  let paramCount = 1; // track the param count used for substitution, not affected by order and executed params

  for (const filter of filters) {
    if (filter.key === constants.filterKeys.LIMIT) {
      filterQuery.limit = filter.value;
      continue;
    }

    if (filter.key === constants.filterKeys.ORDER) {
      filterQuery.order = filter.value;
      continue;
    }

    const columnKey = filterColumnMap[filter.key];
    if (columnKey === undefined) {
      continue;
    }

    // add prefix. 'where' for the 1st param and 'and' for subsequent
    whereQuery += applicableFilters === 0 ? `where ` : ` and `;
    applicableFilters++;

    whereQuery += `${filterColumnMap[filter.key]}${filter.operator}$${paramCount}`;
    paramCount++;
    pgSqlParams.push(filter.value);
  }

  // add limit
  pgSqlParams.push(filterQuery.limit);

  filterQuery.filterQuery = whereQuery;
  filterQuery.params = pgSqlParams;

  return filterQuery;
};
```

**File:** importer/src/main/resources/db/migration/v2/V2.0.3__index_init.sql (L197-201)
```sql
-- schedule
alter table if exists schedule
    add constraint schedule__pk primary key (schedule_id);
create index if not exists schedule__creator_account_id
    on schedule (creator_account_id desc);
```

**File:** rest/api/v1/openapi.yml (L1030-1050)
```yaml
  /api/v1/schedules:
    get:
      summary: List schedules entities
      description: Lists schedules on the network that govern the execution logic of scheduled transactions. This includes executed and non executed schedules.
      operationId: getSchedules
      parameters:
        - $ref: "#/components/parameters/accountIdQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
        - $ref: "#/components/parameters/scheduleIdQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SchedulesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - schedules
```
