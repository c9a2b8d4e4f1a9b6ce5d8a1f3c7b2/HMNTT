### Title
Silent Duration Parse Failure in `toDuration()` Masks Invalid `HIERO_MIRROR_PINGER_INTERVAL`, Causing Uncontrolled Transaction Rate

### Summary
`toDuration()` in `pinger/config.go` silently returns `1 * time.Second` when `time.ParseDuration` fails, with no error returned and no warning logged. When `HIERO_MIRROR_PINGER_INTERVAL` is set to an invalid duration string, `loadConfig()` uses this silent fallback as the `flag.DurationVar` default, the post-parse validation passes because `1s > 0`, and the pinger proceeds to submit Hedera transactions every second — potentially far more frequently than intended — with no indication that the configuration was invalid.

### Finding Description
**Code path:**

- `pinger/config.go` line 55: `intervalStr := envOr("HIERO_MIRROR_PINGER_INTERVAL", "1s")`
- `pinger/config.go` line 56: `flag.DurationVar(&cfg.interval, "interval", toDuration(intervalStr), ...)`
- `pinger/config.go` lines 147–153: `toDuration()` calls `time.ParseDuration`; on error, silently returns `1 * time.Second`
- `pinger/config.go` line 114: `if cfg.interval <= 0` — the only post-parse validation

**Root cause:** `toDuration()` is used to compute the *default value* passed to `flag.DurationVar`, not as a flag value parser. When `HIERO_MIRROR_PINGER_INTERVAL` contains an invalid string (e.g., `"1minute"`, `"INVALID"`, `"60"`), `envOr()` returns that string, `toDuration()` fails to parse it and silently returns `1 * time.Second`, and `flag.DurationVar` registers `1s` as the default. Since no `-interval` CLI flag is present, `flag.Parse()` leaves `cfg.interval = 1s`. The validation at line 114 only rejects non-positive values; `1s > 0` passes cleanly. No error is ever returned from `loadConfig()`, and no warning is ever logged about the invalid input.

**Why existing checks fail:** The `cfg.interval <= 0` guard at line 114 is designed to catch zero/negative values, not to detect that the configured string was unparseable. The silent fallback in `toDuration()` converts an invalid input into a valid positive duration before the guard is ever reached.

### Impact Explanation
An attacker (or misconfigured deployment) that sets `HIERO_MIRROR_PINGER_INTERVAL` to any invalid duration string causes the pinger to fire every 1 second unconditionally. If the intended interval was `1m` (60 seconds), this results in 60× the intended transaction rate against the Hedera network — each tick calls `submitWithRetry`, which submits a real signed crypto-transfer transaction consuming real tinybar from the operator account. At scale or over time this constitutes unintended financial drain and potential rate-limit exhaustion on the operator account. The misconfiguration is completely invisible: `loadConfig()` returns no error, and the only observable signal is the log line in `main.go` line 51–52 printing `"every 1s"` — which an operator may not notice is wrong if `1s` happens to look plausible.

### Likelihood Explanation
Any party able to set environment variables in the pinger's execution environment can trigger this. In Kubernetes this means write access to the Deployment/ConfigMap; in Docker Compose it means access to the compose file or `.env`; in CI/CD pipelines it means the ability to inject env vars into the job. This is a realistic capability for a developer, a compromised CI token, or a misconfigured RBAC policy — none of which require root or cluster-admin privileges. The trigger is trivially repeatable: a single env-var change, no special tooling required.

### Recommendation
Replace the silent-fallback pattern with explicit error propagation. `toDuration()` should return `(time.Duration, error)` and `loadConfig()` should return an error immediately if parsing fails:

```go
func toDuration(s string) (time.Duration, error) {
    d, err := time.ParseDuration(strings.TrimSpace(s))
    if err != nil {
        return 0, fmt.Errorf("invalid duration %q: %w", s, err)
    }
    return d, nil
}
```

Then in `loadConfig()`:
```go
intervalDur, err := toDuration(intervalStr)
if err != nil {
    return cfg, fmt.Errorf("HIERO_MIRROR_PINGER_INTERVAL: %w", err)
}
flag.DurationVar(&cfg.interval, "interval", intervalDur, "...")
```

Apply the same fix to all other `toDuration()` call sites (`base-backoff`, `mirror-node-client-base-backoff`, `mirror-node-client-retry-timeout`).

### Proof of Concept
```bash
# Set an invalid duration (Go's time.ParseDuration requires a unit suffix like s/ms/m)
export HIERO_MIRROR_PINGER_INTERVAL="60"          # missing unit — invalid
# or
export HIERO_MIRROR_PINGER_INTERVAL="1minute"     # wrong unit name — invalid
# or
export HIERO_MIRROR_PINGER_INTERVAL="NOTADURATION"

# Run the pinger (with valid operator credentials)
./pinger

# Observed output — no config error, pinger starts at 1s:
# pinger starting (version=development)
# Starting transfer ticker: every 1s, 10000 tinybar from 0.0.2 -> 0.0.98 on testnet

# Expected: loadConfig() should return an error and the process should exit with a
# "config error: HIERO_MIRROR_PINGER_INTERVAL: invalid duration ..." message.
# Instead: pinger silently runs at 1s intervals, submitting transactions 60× faster
# than the operator intended (if they meant "60s"), with no indication of the mistake.
```