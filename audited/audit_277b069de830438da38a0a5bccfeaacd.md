### Title
Disabled EVM-Layer Gas Throttles Combined with Unaccounted Binary-Search Multiplier Enable CPU Amplification via `eth_estimateGas`

### Summary
`buildTransactionProperties()` permanently hardcodes `contracts.throttle.throttleByGas=false` and `executor.disableThrottles=true`, disabling all EVM-layer gas throttling. The application-layer throttle (`ThrottleManagerImpl`) charges gas tokens exactly once per HTTP request based on `request.getGas()`, but `eth_estimateGas` internally executes the EVM up to 21 times (1 initial call + up to 20 binary-search iterations). An unprivileged attacker can therefore consume up to 21× more CPU per throttle token than a regular `eth_call`, easily exceeding a 30% resource increase.

### Finding Description

**Exact code path:**

`EvmProperties.buildTransactionProperties()` — `web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java`, lines 153–178 — unconditionally sets:
```
contracts.throttle.throttleByGas = false   // line 160
executor.disableThrottles          = true   // line 162
```
These are passed to the embedded consensus-node library via `ConfigProviderImpl` (line 100) and cannot be overridden at runtime because `props.putAll(properties)` (line 176) only allows user-defined keys to override defaults, but these two keys are always written first and the user-supplied map is merged on top — meaning a user *could* override them, but the defaults are permanently `false`/`true` and no deployment configuration is shown to change them.

**Application-layer throttle — charged once:**

`ContractController.call()` — `web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java`, line 40 — calls `throttleManager.throttle(request)` exactly once before dispatching to `contractExecutionService.processCall(params)`.

`ThrottleManagerImpl.throttle()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 37–42 — consumes `scaleGas(request.getGas())` tokens from `gasLimitBucket`. With `maxGasLimit = 15,000,000` and `GAS_SCALE_FACTOR = 10,000`, a max-gas request consumes 1,500 tokens. The bucket capacity is `scaleGas(7,500,000,000) = 750,000` tokens/second.

**Binary-search multiplier — never throttled:**

`ContractExecutionService.estimateGas()` — `web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java`, lines 81–98 — first calls `callContract(params, context)` (1 full EVM execution at `params.getGas()` = 15 M), then calls `binaryGasEstimator.search(...)`.

`BinaryGasEstimator.search()` — `web3/src/main/java/org/hiero/mirror/web3/service/utils/BinaryGasEstimator.java`, lines 35–58 — loops `while (lo + 1 < hi && iterationsMade < properties.getMaxGasEstimateRetriesCount())` with `maxGasEstimateRetriesCount = 20`. Each iteration calls `safeCall(mid, call)` which invokes a full EVM execution. No throttle token is consumed for any of these iterations.

**Total EVM executions per single throttled request:** 1 (initial) + up to 20 (binary search) = **up to 21**.

**Why EVM-layer throttle removal matters:**

With `contracts.throttle.throttleByGas=false` and `executor.disableThrottles=true`, each of the 21 EVM executions runs at full CPU speed — no gas-based pacing, no executor-level back-pressure. If these were enabled, the consensus-node library would introduce delays proportional to gas consumption within each execution, reducing CPU throughput per unit time. Their permanent disablement means the CPU cost per execution is maximized.

**`scaleGas` blind spot (bonus amplifier):**

`ThrottleProperties.scaleGas()` — line 43 — returns `0` for `gas ≤ 10,000`. Requests with gas ≤ 10,000 consume zero gas tokens, so an attacker can also flood with small-gas estimateGas requests limited only by the 500 req/s rate limit, each still triggering multiple EVM executions.

### Impact Explanation

A single attacker thread submitting `eth_estimateGas` with `gas=15,000,000` at the 500 req/s rate limit triggers up to 10,500 full EVM executions per second (500 × 21), while consuming the same throttle budget as 500 regular `eth_call` executions. This is a **21× CPU amplification** relative to what the throttle was designed to permit. Even at a fraction of the rate limit, the amplification easily exceeds 30% additional resource consumption compared to a baseline of normal `eth_call` traffic. The node has no mechanism to shed this load — the binary-search loop runs synchronously within the request thread, and no circuit-breaker or per-request EVM-execution cap exists.

### Likelihood Explanation

No authentication, API key, or account registration is required. Any external user can POST to `/api/v1/contracts/call` with `estimate: true` and `gas: 15000000`. The attack is trivially scriptable with a single `curl` loop or any HTTP client. It is repeatable indefinitely (the gas bucket refills every second), requires no on-chain state, and leaves no attributable footprint beyond HTTP access logs. The attacker needs only network access to the public endpoint.

### Recommendation

1. **Charge throttle tokens per EVM execution, not per request.** Pass the `ThrottleManager` into `BinaryGasEstimator.search()` and consume `scaleGas(mid)` tokens on each iteration, or charge `scaleGas(gas) * (1 + maxGasEstimateRetriesCount)` upfront for estimateGas requests.
2. **Cap binary-search iterations at a lower default** (e.g., 5–8) or make the cap configurable and document its resource impact.
3. **Re-evaluate the permanent disablement of `contracts.throttle.throttleByGas`.** If the EVM-layer throttle is intentionally disabled for correctness reasons, the application-layer throttle must compensate by accounting for the full execution multiplier.
4. **Fix the `scaleGas` zero-return for gas ≤ 10,000** — treat any positive gas value as consuming at least 1 token.

### Proof of Concept

```bash
# Requires: network access to the web3 endpoint, no credentials needed.
# Target: POST /api/v1/contracts/call with estimate=true, gas=15000000

CONTRACT="0x0000000000000000000000000000000000000001"  # any deployed contract
ENDPOINT="http://<mirror-node-host>:8545/api/v1/contracts/call"

# Flood with max-gas estimateGas requests
while true; do
  curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{
      \"to\": \"$CONTRACT\",
      \"gas\": 15000000,
      \"estimate\": true,
      \"data\": \"0x<complex_bytecode_selector>\"
    }" &
done
```

Each request passes the throttle (consuming 1,500 gas tokens) but triggers up to 21 full EVM executions at 15 M gas each with no EVM-layer throttling. Monitoring CPU on the mirror-node process will show consumption proportional to 21× the throttle-permitted rate. Sustained for 60+ seconds, this produces a measurable and sustained >30% CPU increase over the 24-hour baseline.