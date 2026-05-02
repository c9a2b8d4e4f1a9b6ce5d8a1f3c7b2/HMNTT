### Title
No Upper-Bound Validation on `HIERO_MIRROR_REST_QUERY_MAXTIMESTAMPRANGE` Allows `maxTimestampRange` Guard Bypass via Environment Variable Injection

### Summary
`setConfigValue()` in `rest/config.js` unconditionally writes any syntactically valid duration string supplied via the `HIERO_MIRROR_REST_QUERY_MAXTIMESTAMPRANGE` environment variable into the live config object. `parseDurationConfig()` only rejects values that `parseDuration()` cannot parse (returns falsy), but imposes no upper-bound limit, so a value such as `9999d` or `100y` is accepted and stored as an astronomically large `maxTimestampRangeNs`. The guard in `parseTimestampFilters()` that enforces the timestamp window then becomes permanently ineffective, allowing any client to issue unbounded timestamp-range queries that exhaust the database and deny service to all transaction endpoints.

### Finding Description

**Code path:**

1. **`rest/config.js` `loadEnvironment()` → `setConfigValue()` (lines 58–113)**
   `loadEnvironment()` iterates every process environment variable and calls `setConfigValue(key, value)`. Inside `setConfigValue`, the key `HIERO_MIRROR_REST_QUERY_MAXTIMESTAMPRANGE` is lowercased and split on `_`, producing the path `hiero → mirror → rest → query → maxTimestampRange`. The function walks the live `config` object, finds the matching leaf key, and writes `convertType(value)` directly into it (line 100). `convertType` returns the raw string unchanged for non-numeric, non-boolean values such as `"9999d"`.

2. **`rest/config.js` `parseDurationConfig()` (lines 150–156)**
   ```js
   const parseDurationConfig = (name, value) => {
     const ms = parseDuration(value);
     if (!ms) {
       throw new InvalidConfigError(`invalid ${name} ${value}`);
     }
     return BigInt(ms) * NANOSECONDS_PER_MILLISECOND;
   };
   ```
   The only validation is `if (!ms)` — a falsy check. Any syntactically valid duration string (`"9999d"`, `"100y"`, `"999999h"`) produces a large positive millisecond value, passes the check, and is multiplied into nanoseconds. There is **no maximum value check**.

3. **`rest/config.js` `parseQueryConfig()` (lines 167–176)**
   Calls `parseDurationConfig` for every key in `durationQueryConfigKeys`, including `maxTimestampRange`, and stores the result in `query.maxTimestampRangeNs`.

4. **`rest/utils.js` `parseTimestampFilters()` (lines 1657–1665)**
   ```js
   if (validateRange) {
     const {maxTimestampRange, maxTimestampRangeNs} = config.query;
     if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
       throw new InvalidArgumentError(...);
     }
   }
   ```
   The guard `difference > maxTimestampRangeNs` is the sole enforcement point. If `maxTimestampRangeNs` has been inflated to, e.g., `~3.15 × 10²²` ns (100 years), no realistic client-supplied range will ever exceed it, making the guard permanently dead.

**Root cause:** `parseDurationConfig` validates only format (non-zero parse result), not magnitude. There is no ceiling on what value an operator — or an attacker who can inject environment variables — may configure.

### Impact Explanation
Every REST endpoint that calls `parseTimestampFilters` with `validateRange = true` (the default) relies exclusively on `maxTimestampRangeNs` to bound the timestamp window a client may request. With the guard neutralised, any unauthenticated HTTP client can submit queries spanning years or decades of ledger history. Each such query forces a full sequential scan across potentially billions of rows in the `transaction` table, consuming all available database CPU, I/O, and connection slots. This constitutes a complete denial of service for all transaction-related API endpoints until the service is restarted with a corrected configuration.

### Likelihood Explanation
The precondition — ability to set a single environment variable — is achievable in several realistic scenarios without application-level credentials:
- Overly permissive Kubernetes RBAC that grants `patch` on `Deployment` or `ConfigMap` to a low-privilege service account.
- Exposed cloud-provider instance-metadata endpoints (e.g., AWS IMDSv1) that allow writing user-data or launch-template overrides.
- A compromised sidecar or init container in the same pod that can modify the process environment before the main container starts.
- CI/CD pipeline misconfiguration that allows injection of environment variables into deployment jobs.

Once the environment variable is set and the process restarts (or is first deployed), the bypass is permanent until the variable is removed and the service restarted. The subsequent DoS is trivially repeatable by any HTTP client with no authentication.

### Recommendation
1. **Add an upper-bound check in `parseDurationConfig`**: Define a reasonable maximum (e.g., 30 days) and reject any configured value that exceeds it:
   ```js
   const MAX_ALLOWED_NS = BigInt(30 * 24 * 60 * 60 * 1000) * NANOSECONDS_PER_MILLISECOND;
   const parseDurationConfig = (name, value, maxNs = MAX_ALLOWED_NS) => {
     const ms = parseDuration(value);
     if (!ms) throw new InvalidConfigError(`invalid ${name} ${value}`);
     const ns = BigInt(ms) * NANOSECONDS_PER_MILLISECOND;
     if (ns > maxNs) throw new InvalidConfigError(`${name} ${value} exceeds maximum allowed value`);
     return ns;
   };
   ```
2. **Apply per-key ceilings** in `parseQueryConfig` for each duration key, since each has a different semantic maximum.
3. **Harden the deployment**: Enforce Kubernetes RBAC least-privilege so that no workload identity can patch `Deployment` or `ConfigMap` objects in the mirror-node namespace.

### Proof of Concept

**Precondition:** Attacker has the ability to set one environment variable on the mirror-node REST container (e.g., via a misconfigured Kubernetes RBAC role that allows `patch` on the `Deployment`).

**Steps:**

```bash
# 1. Inject the oversized duration via kubectl (or equivalent)
kubectl set env deployment/hedera-mirror-rest \
  HIERO_MIRROR_REST_QUERY_MAXTIMESTAMPRANGE=9999d

# 2. Wait for the pod to restart and load the new config.
#    setConfigValue() writes "9999d" → config.hiero.mirror.rest.query.maxTimestampRange
#    parseDurationConfig("9999d") → parseDuration("9999d") = 863913600000 ms (truthy, passes)
#    maxTimestampRangeNs = BigInt(863913600000) * 1000000n = 863913600000000000000n  (~27 years)

# 3. Issue an unbounded timestamp-range query from any unauthenticated HTTP client:
curl "https://<mirror-node>/api/v1/transactions?\
timestamp=gte:0000000001.000000000&\
timestamp=lte:9999999999.999999999"

# 4. Observe: the request is accepted (no 400 error), the database executes a
#    full multi-year table scan, CPU/IO spike to 100%, and subsequent requests
#    time out — full DoS achieved.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/config.js (L58-62)
```javascript
function loadEnvironment() {
  for (const [key, value] of Object.entries(process.env)) {
    setConfigValue(key, value);
  }
}
```

**File:** rest/config.js (L69-113)
```javascript
function setConfigValue(propertyPath, value) {
  let current = config;
  const properties = propertyPath.toLowerCase().split('_');

  // Ignore properties that don't start with HEDERA_MIRROR or HIERO_MIRROR
  if (
    properties.length < 3 ||
    (properties[0] !== 'hedera' && properties[0] !== 'hiero') ||
    properties[1] !== 'mirror'
  ) {
    return;
  }

  for (let i = 0; i < properties.length; i += 1) {
    let property = properties[i];
    let found = false;

    for (const [k, v] of Object.entries(current)) {
      if (property === hederaPrefix) {
        property = hieroPrefix;
        logger.warn(
          `Deprecated '${hederaPrefix}' property automatically migrated to '${hieroPrefix}': ${propertyPath}`
        );
      }

      if (property === k.toLowerCase()) {
        if (i < properties.length - 1) {
          current = v;
          found = true;
          break;
        } else {
          current[k] = convertType(value);
          const cleanedValue =
            property.includes('password') || property.includes('key') || property.includes('uri') ? '******' : value;
          logger.info(`Override config with environment variable ${propertyPath}=${cleanedValue}`);
          return;
        }
      }
    }

    if (!found) {
      return;
    }
  }
}
```

**File:** rest/config.js (L150-156)
```javascript
const parseDurationConfig = (name, value) => {
  const ms = parseDuration(value);
  if (!ms) {
    throw new InvalidConfigError(`invalid ${name} ${value}`);
  }
  return BigInt(ms) * NANOSECONDS_PER_MILLISECOND;
};
```

**File:** rest/config.js (L167-176)
```javascript
const parseQueryConfig = () => {
  const {query} = getConfig();
  const {precedingTransactionTypes} = query.transactions;
  if (!Array.isArray(precedingTransactionTypes)) {
    throw new InvalidConfigError(
      `Invalid or missing query.transactions.precedingTransactionTypes: ${precedingTransactionTypes}`
    );
  }
  durationQueryConfigKeys.forEach((key) => (query[`${key}Ns`] = parseDurationConfig(`query.${key}`, query[key])));
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
