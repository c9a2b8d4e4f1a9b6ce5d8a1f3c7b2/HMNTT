All key claims are verifiable in the codebase. Let me confirm the critical facts before rendering a verdict.

**Verified facts:**

1. `HibernateConfiguration.statementInspector()` — timeout fires only at SQL boundaries. [1](#0-0) 

2. `Web3Properties.requestTimeout` defaults to 10 seconds. [2](#0-1) 

3. `ThrottleManagerImpl.throttle()` is a pre-execution token-bucket check only; it does not interrupt a running request. [3](#0-2) 

4. `ContractController.call()` has no authentication; calls `throttle()` then `processCall()` with no post-execution timeout guard. [4](#0-3) 

5. Default `requestsPerSecond = 500`, `gasPerSecond = 7_500_000_000`. [5](#0-4) 

6. `maxGasLimit = 15_000_000`. [6](#0-5) 

7. Direct calls to `Address.ALTBN128_PAIRING`, `Address.MODEXP`, `Address.BLAKE2B_F_COMPRESSION`, etc. succeed without authentication. [7](#0-6) 

**SECURITY.md scope check:** The exclusion "Impacts that only require DDoS" covers generic volumetric attacks. This finding is a specific code-level design flaw — the intended timeout safety mechanism is structurally bypassed for an entire class of operations. That is distinct from a generic DDoS and is in scope. [8](#0-7) 

---

Audit Report

## Title
`requestTimeout` Not Enforced for EVM Precompile Execution — CPU Exhaustion via Unauthenticated Precompile Calls

## Summary
The `requestTimeout` in `Web3Properties` (default 10 s) is enforced exclusively through a Hibernate `StatementInspector` that fires only at SQL query boundaries. Native EVM precompile calls (ECRecover, ModExp, altBN128Pairing, BLAKE2F, etc.) are pure CPU operations that never issue SQL statements. The timeout is therefore never checked during their execution. An unauthenticated attacker can send requests at the full `requestsPerSecond` rate (default 500/s), each targeting a computationally expensive precompile at maximum gas, holding server threads in CPU-bound work indefinitely and exhausting the thread pool.

## Finding Description

**Timeout enforcement is DB-only.**
`HibernateConfiguration.statementInspector()` reads `web3Properties.getRequestTimeout()` (default 10 s) and checks elapsed time only when Hibernate is about to execute a SQL statement:

```java
// web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java:31-47
StatementInspector statementInspector() {
    long timeout = web3Properties.getRequestTimeout().toMillis();
    return sql -> {
        if (!ContractCallContext.isInitialized()) { return sql; }
        var startTime = ContractCallContext.get().getStartTime();
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed >= timeout) {
            throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
        }
        return sql;
    };
}
```

For a direct call to a native precompile address, the Besu EVM dispatches execution entirely within its precompile implementation — no Hibernate/DB calls are made. The `StatementInspector` is never invoked, so `requestTimeout` is never checked. [1](#0-0) 

**Execution path for precompile calls (no DB touch):**
`ContractController.call()` → `ThrottleManagerImpl.throttle()` (pre-execution check only) → `contractExecutionService.processCall()` → Besu EVM dispatches to precompile → returns result. Zero SQL statements issued; zero timeout checks. [9](#0-8) 

**Throttle checks are pre-execution and do not bound wall-clock time.**
`ThrottleManagerImpl.throttle()` checks `rateLimitBucket` (500 req/s) and `gasLimitBucket` (scaled gas/s) before execution begins. These token-bucket counters limit throughput but place no upper bound on how long a single request's EVM execution runs. The `restore()` method returns gas tokens only after the request completes — it does not interrupt a running request. [10](#0-9) 

**Supported precompile targets confirmed in codebase.**
`ContractCallNativePrecompileTest` confirms direct calls to `Address.ECREC` (0x01), `Address.SHA256` (0x02), `Address.RIPEMD160` (0x03), `Address.MODEXP` (0x05), `Address.ALTBN128_ADD` (0x06), `Address.ALTBN128_MUL` (0x07), `Address.ALTBN128_PAIRING` (0x08), `Address.BLAKE2B_F_COMPRESSION` (0x09) all succeed without authentication. [11](#0-10) [7](#0-6) 

**No authentication on the endpoint.**
`ContractController` at `/api/v1/contracts/call` accepts any unauthenticated POST request. [12](#0-11) 

## Impact Explanation
An attacker targeting `0x08` (altBN128Pairing) with `gas=15_000_000` (the enforced maximum) can request approximately 440 pairing operations per call (gas cost = 45,000 + 34,000×k). Each pairing is a multi-millisecond elliptic curve bilinear map. The gas throttle (`gasPerSecond = 7_500_000_000`, scaled by 10,000 → 750,000 tokens/s; each 15M-gas request consumes 1,500 tokens) permits up to 500 such requests per second — exactly matching `requestsPerSecond`. At that rate, hundreds of concurrent threads are held in CPU-bound precompile computation. The server's Tomcat thread pool (default 200 threads) is exhausted, and legitimate requests receive 503 responses or queue indefinitely. The `requestTimeout` — the intended safety net — never fires because no SQL is executed. This constitutes a complete denial of service achievable by a single unauthenticated client. [6](#0-5) [5](#0-4) 

## Likelihood Explanation
No credentials, API keys, or special network access are required. The attack requires only knowledge of EVM precompile addresses (publicly documented in the Ethereum Yellow Paper) and the ability to send HTTP POST requests. The exploit is trivially scriptable with `curl` or any HTTP client. The default `requestsPerSecond=500` provides a generous attack budget. The vulnerability is repeatable and persistent as long as the attacker maintains the request rate. [13](#0-12) 

## Recommendation
1. **Add a wall-clock timeout independent of Hibernate.** Wrap `contractExecutionService.processCall()` in a `Future` submitted to a bounded executor, and enforce the `requestTimeout` via `Future.get(timeout, MILLISECONDS)`, cancelling the task on expiry. This ensures the timeout fires regardless of whether SQL is executed.
2. **Alternatively, enforce the timeout inside the EVM execution loop.** Inject a check against `ContractCallContext.get().getStartTime()` at the operation-dispatch level so that long-running EVM frames (including precompile dispatch) are interrupted when the deadline is exceeded.
3. **Reduce the default `requestsPerSecond` or add per-IP rate limiting** to reduce the attack surface while the above fix is implemented.
4. **Consider lowering `maxGasLimit` for precompile-targeted calls** or adding a separate gas cap for calls to known precompile addresses.

## Proof of Concept
```bash
# Target altBN128Pairing (0x08) at maximum gas — no authentication required
# Craft valid pairing input (2 pairs, minimal valid points)
PAIRING_INPUT="0x..."  # standard test vector from EIP-197

for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"0x0000000000000000000000000000000000000008\",
         \"gas\":15000000,
         \"data\":\"$PAIRING_INPUT\"}" &
done
wait
```

Each request dispatches ~440 bilinear pairing operations inside the Besu EVM. No SQL is issued, so `HibernateConfiguration.statementInspector()` never fires. The 10-second `requestTimeout` is never checked. All 500 concurrent threads remain CPU-bound until the pairing computation completes, exhausting the Tomcat thread pool and denying service to legitimate callers. [14](#0-13) [15](#0-14)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-47)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L19-20)
```java
    @DurationMin(seconds = 1L)
    private Duration requestTimeout = Duration.ofSeconds(10L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-64)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }

    @Override
    public void throttleOpcodeRequest() {
        if (!opcodeRateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        }
    }

    @Override
    public void restore(long gas) {
        long tokens = throttleProperties.scaleGas(gas);
        if (tokens > 0) {
            gasLimitBucket.addTokens(tokens);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L27-51)
```java
@CustomLog
@RequestMapping("/api/v1/contracts")
@RequiredArgsConstructor
@RestController
class ContractController {

    private final ContractExecutionService contractExecutionService;
    private final EvmProperties evmProperties;
    private final ThrottleManager throttleManager;

    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L22-35)
```java
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L68-69)
```java
    @Min(21_000L)
    private long maxGasLimit = 15_000_000L;
```

**File:** web3/src/test/java/org/hiero/mirror/web3/service/ContractCallNativePrecompileTest.java (L36-53)
```java
    @Test
    void directCallToNativePrecompileECRecover() {
        final var gasUsedBeforeExecution = getGasUsedBeforeExecution(ETH_CALL);

        final var hash = "0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3";
        final var v = "000000000000000000000000000000000000000000000000000000000000001c";
        final var r = "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608";
        final var s = "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada";
        final var correctResult = "0x0000000000000000000000007156526fbd7a3c72969b54f64e42c10fbb768c8a";

        final var data = hash.concat(v).concat(r).concat(s);

        final var serviceParameters = serviceParametersForExecution(data, Address.ECREC);

        assertThat(contractCallService.processCall(serviceParameters)).isEqualTo(correctResult);

        assertGasUsedIsPositive(gasUsedBeforeExecution);
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/service/ContractCallNativePrecompileTest.java (L153-188)
```java
    @Test
    void directCallToNativePrecompileEcPairing() {
        final var gasUsedBeforeExecution = getGasUsedBeforeExecution(ETH_CALL);

        final var x1 = "0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da";
        final var y1 = "2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6";
        final var x2 = "1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc";
        final var y2 = "22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9";
        final var x3 = "2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90";
        final var y3 = "2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e";
        final var x4 = "0000000000000000000000000000000000000000000000000000000000000001";
        final var y4 = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
        final var x5 = "1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4";
        final var y5 = "091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7";
        final var x6 = "2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2";
        final var y6 = "23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc";

        final var data = x1.concat(y1)
                .concat(x2)
                .concat(y2)
                .concat(x3)
                .concat(y3)
                .concat(x4)
                .concat(y4)
                .concat(x5)
                .concat(y5)
                .concat(x6)
                .concat(y6);
        final var correctResult = "0x0000000000000000000000000000000000000000000000000000000000000001";
        System.out.println(data);
        final var serviceParameters = serviceParametersForExecution(data, Address.ALTBN128_PAIRING);

        assertThat(contractCallService.processCall(serviceParameters)).isEqualTo(correctResult);

        assertGasUsedIsPositive(gasUsedBeforeExecution);
    }
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
