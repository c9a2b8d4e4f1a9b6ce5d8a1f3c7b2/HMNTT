### Title
Default Gas Value Equals Maximum Gas Limit, Enabling Throttle Bucket Exhaustion with Minimal Request Crafting

### Summary
`ContractCallRequest` defaults the `gas` field to `15_000_000`, which is identical to the configured `maxGasLimit`. Because `ThrottleManagerImpl.throttle()` consumes gas tokens from the bucket **before** execution and **before** any per-request gas validation, every request omitting the `gas` field immediately drains the maximum possible tokens. A single unauthenticated attacker sending 500 minimal requests per second (the global rate cap) can fully exhaust the gas throttle bucket each second, denying service to all other users.

### Finding Description

**Root cause — default gas equals the maximum:**

`ContractCallRequest.java` line 37 sets the default:
```java
@Min(21_000)
private long gas = 15_000_000L;
```
`EvmProperties.java` line 65 sets the ceiling:
```java
@Min(21_000L)
private long maxGasLimit = 15_000_000L;
```
These two values are identical, so any request that omits the `gas` field silently claims the maximum allowed gas.

**Token consumption path:**

In `ContractController.call()` (lines 40–41), throttling occurs first:
```java
throttleManager.throttle(request);       // consumes tokens
validateContractMaxGasLimit(request);    // runs after
```
`ThrottleManagerImpl.throttle()` (line 40) immediately deducts scaled tokens:
```java
gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))
```
`ThrottleProperties.scaleGas(15_000_000)` = `Math.floorDiv(15_000_000, 10_000)` = **1,500 tokens** per request.

**Bucket capacity:**

Default `gasPerSecond = 7_500_000_000L` → `scaleGas(7_500_000_000)` = **750,000 tokens/second** bucket capacity.

**Exhaustion arithmetic:**

`requestsPerSecond = 500` (global rate limit). At 500 req/s × 1,500 tokens/req = **750,000 tokens/second** — exactly the full bucket capacity. An attacker sending 500 requests/second with no `gas` field drains the entire gas bucket every second.

**Why the restore mechanism does not prevent this:**

`restoreGasToBucket()` in `ContractCallService.java` (lines 140–151) returns unused gas **after** execution completes. During the execution window — which can span tens to hundreds of milliseconds for complex calls — all 750,000 tokens are already consumed. Any concurrent legitimate request arriving during that window receives `GAS_PER_SECOND_LIMIT_EXCEEDED`. The restore is asynchronous relative to incoming requests; it does not prevent the bucket from hitting zero.

The `InvalidParametersException` catch in `ContractController` (lines 46–49) restores gas only for validation failures. Since `15_000_000 > 15_000_000` is false, `validateContractMaxGasLimit` never throws for the default value, so no early restore occurs.

### Impact Explanation
Any unauthenticated user can send a flood of syntactically valid, minimal POST requests (e.g., `{"to":"0x00000000000000000000000000000000000004e2"}`) and monopolize the entire gas throttle budget. All other users — including legitimate callers who specify a reasonable gas value — receive HTTP 429 `Gas per second rate limit exceeded` for the duration of the attack. The global rate-limit bucket (500 req/s) does not protect against this because the attacker's requests are individually valid and consume the rate-limit slot along with the maximum gas tokens simultaneously.

### Likelihood Explanation
No authentication, API key, or IP-based rate limiting is required. The attacker needs only a valid `to` address (any 20-byte hex value) and the ability to sustain ~500 HTTP POST requests per second, achievable from a single machine or a small botnet. The attack is trivially scriptable (`curl` in a loop or any HTTP load tool), repeatable indefinitely, and requires zero knowledge of contract internals.

### Recommendation
1. **Change the default gas to the minimum, not the maximum.** Set `private long gas = 21_000L` in `ContractCallRequest`. Users who need more gas must explicitly request it.
2. **Alternatively, require the `gas` field explicitly** (add `@NotNull` / remove the default) so that omitting it results in a 400 Bad Request rather than silently claiming maximum tokens.
3. **Add per-source-IP throttling** so a single client cannot monopolize the global gas bucket.
4. **Move gas token consumption to after validation** (or at least after `validateContractMaxGasLimit`) so that requests that will be rejected never consume throttle tokens.

### Proof of Concept
```bash
# Minimal request — no gas field, defaults to 15,000,000
for i in $(seq 1 500); do
  curl -s -o /dev/null -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x00000000000000000000000000000000000004e2"}' &
done
wait

# Immediately after, a legitimate request with explicit low gas is rejected:
curl -X POST https://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x00000000000000000000000000000000000004e2","gas":21000}'
# Response: 429 Too Many Requests — "Gas per second rate limit exceeded."
```

The 500 concurrent requests each consume 1,500 scaled tokens, totalling 750,000 — the full bucket capacity — leaving zero tokens for any concurrent or immediately subsequent legitimate caller.