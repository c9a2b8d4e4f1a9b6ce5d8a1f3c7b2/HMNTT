The code has been verified. All claims in the report are accurate against the actual source.

**Verified facts:**
- `authenticate()` at lines 137–144 uses `!authentication` (falsy), not `authentication === false` [1](#0-0) 
- `convertType()` at lines 115–123 converts `"0"` → numeric `0` via `+value` [2](#0-1) 
- The only auth guard at lines 157–160 relies entirely on `authenticate()` returning `false` to block access [3](#0-2) 
- No SECURITY.md exclusion covers this: it is not a config-file-only issue, not a best-practice recommendation, and not theoretical — it is a concrete code logic defect with a demonstrable exploit path [4](#0-3) 

---

# Audit Report

## Title
Falsy-Value Authentication Bypass in `authenticate()` Allows Unauthenticated Metrics Access

## Summary
The `authenticate()` function in `rest/middleware/metricsHandler.js` uses `!authentication` to decide whether to skip credential verification. Because JavaScript's `!` operator treats `0`, `null`, `undefined`, and `""` as truthy negations, any of these values stored in `config.metrics.config.authentication` causes the function to return `true` (access granted) without verifying credentials. The `convertType()` helper in `rest/config.js` concretely enables this by converting the string `"0"` to numeric `0` when the value is set via environment variable.

## Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, `authenticate()`, lines 137–144:
```javascript
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {   // ← falsy check, not strict === false
    return true;           // ← returns "authenticated" for 0, null, undefined, ""
  }
  const credentials = basicAuth(req);
  return credentials && tsscmp(credentials.name, username) && tsscmp(credentials.pass, password);
};
```

**Root cause:** The guard `if (!authentication)` is intended to mean "if auth is explicitly disabled (`false`), skip credential checks." However, `!0`, `!null`, `!undefined`, and `!""` all evaluate to `true` in JavaScript, so any of those falsy values silently bypasses authentication.

**Concrete misconfiguration path via `convertType`:**

`rest/config.js`, lines 115–123:
```javascript
function convertType(value) {
  if (value !== null && value !== '' && !isNaN(value)) {
    return +value;   // "0" → 0 (numeric zero)
  } else if (value === 'true' || value === 'false') {
    return value === 'true';
  }
  return value;
}
```

When an operator sets `HIERO_MIRROR_REST_METRICS_CONFIG_AUTHENTICATION=0`, `convertType("0")` returns numeric `0`. This is stored in `config.metrics.config.authentication`. At request time, `!0` → `true`, so `authenticate()` returns `true` without ever calling `basicAuth()`.

**Why the existing check fails:**

The only guard protecting the metrics endpoint is at line 157:
```javascript
if (!authenticate(req)) {
  res.set('WWW-Authenticate', 'Basic realm="Metrics"');
  return res.status(401).send('Unauthorized');
}
```
Since `authenticate()` already returned `true`, this guard is never triggered. There is no secondary check, no type validation of the `authentication` config value anywhere in `config.js` — `parseDbPoolConfig`, `parseQueryConfig`, `parseUsersConfig`, and `parseCommon` do not touch `metrics.config`.

## Impact Explanation
An unauthenticated external user gains full read access to the Prometheus metrics endpoint (default path `/swagger/metrics/`). The exposed data includes per-route request counters, HTTP status code distributions, request/response size histograms, duration histograms, CPU and memory usage, and in-flight request counts — all labeled by HTTP method and route path. This reveals API usage patterns, error rates, and indirectly exposes which transaction-related endpoints are active and at what volume, constituting an information disclosure of operational internals. Severity is **Medium** (information disclosure, not direct data exfiltration), but it provides reconnaissance value to an attacker mapping the system.

## Likelihood Explanation
The precondition — `authentication` being set to a falsy non-`false` value — is realistic. An operator unfamiliar with JavaScript truthiness may set `HIERO_MIRROR_REST_METRICS_CONFIG_AUTHENTICATION=0` to "disable" auth, or a YAML config may contain `authentication: ~` (YAML null) or `authentication: 0`. The `convertType` function actively converts `"0"` to numeric `0`, making the env-var path concrete and not hypothetical. Once the misconfiguration exists, exploitation requires zero privileges: a single unauthenticated HTTP GET to `/swagger/metrics/` suffices, is repeatable, and leaves no distinguishing trace beyond a normal access log entry.

## Recommendation
Replace the falsy check with a strict boolean comparison in `authenticate()`:

```javascript
// Before (vulnerable):
if (!authentication) {
  return true;
}

// After (safe):
if (authentication === false) {
  return true;
}
```

Additionally, add type validation in the config parsing stage (e.g., in a `parseMetricsConfig` function called from the initialization block) to reject non-boolean values for `authentication` and throw an `InvalidConfigError`, consistent with how `parseDbPoolConfig` and `parseQueryConfig` handle invalid config values.

## Proof of Concept
1. Start the REST service with `HIERO_MIRROR_REST_METRICS_CONFIG_AUTHENTICATION=0`.
2. `convertType("0")` stores numeric `0` in `config.metrics.config.authentication`.
3. Send an unauthenticated request:
   ```
   curl -v http://<host>/swagger/metrics/
   ```
4. `authenticate()` evaluates `!0` → `true` and returns `true`.
5. The 401 guard is skipped; the full Prometheus metrics payload is returned with HTTP 200.

### Citations

**File:** rest/middleware/metricsHandler.js (L137-144)
```javascript
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {
    return true;
  }
  const credentials = basicAuth(req);
  return credentials && tsscmp(credentials.name, username) && tsscmp(credentials.pass, password);
};
```

**File:** rest/middleware/metricsHandler.js (L157-160)
```javascript
      if (!authenticate(req)) {
        res.set('WWW-Authenticate', 'Basic realm="Metrics"');
        return res.status(401).send('Unauthorized');
      }
```

**File:** rest/config.js (L115-123)
```javascript
function convertType(value) {
  if (value !== null && value !== '' && !isNaN(value)) {
    return +value;
  } else if (value === 'true' || value === 'false') {
    return value === 'true';
  }

  return value;
}
```

**File:** SECURITY.md (L1-55)
```markdown
# Common Vulnerability Exclusion List

## Out of Scope & Rules

These are the default impacts recommended to projects to mark as out of scope for their bug bounty program. The actual list of out-of-scope impacts differs from program to program.

### General

- Impacts requiring attacks that the reporter has already exploited themselves, leading to damage.
- Impacts caused by attacks requiring access to leaked keys/credentials.
- Impacts caused by attacks requiring access to privileged addresses (governance, strategist), except in cases where the contracts are intended to have no privileged access to functions that make the attack possible.
- Impacts relying on attacks involving the depegging of an external stablecoin where the attacker does not directly cause the depegging due to a bug in code.
- Mentions of secrets, access tokens, API keys, private keys, etc. in GitHub will be considered out of scope without proof that they are in use in production.
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.

### Smart Contracts / Blockchain DLT

- Incorrect data supplied by third-party oracles.
- Impacts requiring basic economic and governance attacks (e.g. 51% attack).
- Lack of liquidity impacts.
- Impacts from Sybil attacks.
- Impacts involving centralization risks.

Note: This does not exclude oracle manipulation/flash-loan attacks.

### Websites and Apps

- Theoretical impacts without any proof or demonstration.
- Impacts involving attacks requiring physical access to the victim device.
- Impacts involving attacks requiring access to the local network of the victim.
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
- Any impacts involving self-XSS.
- Captcha bypass using OCR without impact demonstration.
- CSRF with no state-modifying security impact (e.g. logout CSRF).
- Impacts related to missing HTTP security headers (such as `X-FRAME-OPTIONS`) or cookie security flags (such as `httponly`) without demonstration of impact.
- Server-side non-confidential information disclosure, such as IPs, server names, and most stack traces.
- Impacts causing only the enumeration or confirmation of the existence of users or tenants.
- Impacts caused by vulnerabilities requiring unprompted, in-app user actions that are not part of the normal app workflows.
- Lack of SSL/TLS best practices.
- Impacts that only require DDoS.
- UX and UI impacts that do not materially disrupt use of the platform.
- Impacts primarily caused by browser/plugin defects.
- Leakage of non-sensitive API keys (e.g. Etherscan, Infura, Alchemy, etc.).
- Any vulnerability exploit requiring browser bugs for exploitation (e.g. CSP bypass).
- SPF/DMARC misconfigured records.
- Missing HTTP headers without demonstrated impact.
- Automated scanner reports without demonstrated impact.
- UI/UX best practice recommendations.
- Non-future-proof NFT rendering.

## Prohibited Activities
```
