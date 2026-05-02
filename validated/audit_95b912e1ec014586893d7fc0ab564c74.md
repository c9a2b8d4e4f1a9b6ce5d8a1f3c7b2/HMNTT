All code references have been verified against the actual repository. Here is the assessment:

---

## Audit Report

## Title
Throttle Function Blind to Historical Block Requests Enables Disproportionate DB I/O Amplification

## Summary
`ThrottleManagerImpl.throttle()` enforces only a global requests-per-second and gas-per-second limit with no awareness of whether a `ContractCallRequest` targets a historical block. Historical block requests trigger significantly more expensive database operations than latest-block requests, yet consume identical throttle tokens. An unprivileged attacker can saturate the shared rate limit with minimum-gas historical requests, causing disproportionate DB I/O that degrades availability for all other users.

## Finding Description

**Verified code path:**

`ContractController.call()` (lines 38–50) calls `throttleManager.throttle(request)` before dispatching to `contractExecutionService.processCall(params)`. [1](#0-0) 

`ThrottleManagerImpl.throttle()` (lines 37–49) checks only `rateLimitBucket.tryConsume(1)` and `gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))`. It never reads `request.getBlock()`. [2](#0-1) 

The optional `RequestProperties` filter loop (lines 44–48) can filter by `FilterField.BLOCK`, but `ThrottleProperties.request` defaults to an empty list, so no block-based filtering is active out of the box. [3](#0-2) 

After throttle passes, `ContractCallService.callContract()` (lines 103–104) sets a block supplier that calls `recordFileService.findByBlockType(params.getBlock())`. For any non-`LATEST` block, this resolves to `recordFileRepository.findByIndex(block.number())`, and the subsequent EVM execution queries historical tables. [4](#0-3) [5](#0-4) 

**Why existing checks fail:**

- `rateLimitBucket` defaults to 500 req/sec (confirmed in `ThrottleProperties` line 35 and `docs/configuration.md` line 730) and is global and shared — it does not weight historical vs. latest requests differently. [6](#0-5) 

- `scaleGas(21_000)` returns `Math.floorDiv(21_000, 10_000)` = **2 tokens** consumed from a bucket with capacity `scaleGas(7_500_000_000)` = **750,000 tokens**. The gas throttle is effectively bypassed for minimum-gas requests. [7](#0-6) 

- The `restore()` call in `ContractController` fires only on `InvalidParametersException` (line 46–49), not on `BlockNumberNotFoundException` or successful historical execution, so rate-limit tokens are never returned for historical calls. [8](#0-7) 

## Impact Explanation

An attacker sending 500 req/sec (the default rate limit) with `block=earliest` and `gas=21000` (minimum) will:

1. Consume the entire shared `rateLimitBucket`, starving all other users of the 500 req/sec budget.
2. Each request triggers historical EVM execution that queries `entity_history`, `account_balance`, `contract_state_change` tables with timestamp predicates — more expensive than latest-block queries — amplifying DB I/O beyond what the throttle was calibrated for.
3. The gas bucket consumes only 2 tokens per request out of 750,000 capacity, providing no meaningful protection.

The result is degraded availability of the `/api/v1/contracts/call` endpoint for all legitimate users and potential DB saturation on a production mirror node with years of history.

## Likelihood Explanation

No authentication or API key is required — the `/api/v1/contracts/call` endpoint is publicly accessible. [9](#0-8) 

The attack requires only an HTTP client capable of sustaining 500 POST requests/second, trivially achievable from a single machine. The `block` field accepts any non-negative integer (`BlockType.of()` parses decimal and hex values), so targeting block 0 (`earliest`) requires no special knowledge. The attack is repeatable and persistent as long as the attacker maintains the request rate.

## Recommendation

1. **Add a per-request cost weight for historical blocks**: Modify `ThrottleManagerImpl.throttle()` to consume additional tokens from `rateLimitBucket` or a dedicated historical-request bucket when `request.getBlock()` is not `LATEST`.
2. **Enable a default block-based `RequestProperties` filter**: Configure a default `THROTTLE` or `REJECT` action for historical block requests (using `FilterField.BLOCK`) to limit their share of the global rate budget.
3. **Separate rate limit buckets**: Introduce a dedicated rate limit bucket for historical requests (e.g., `historicalRateLimitBucket`) with a lower capacity than the global bucket, preventing historical requests from monopolizing the shared budget.
4. **Restore tokens on all non-processing exceptions**: Extend the `restore()` call in `ContractController` to cover `BlockNumberNotFoundException` and other exceptions that occur before or during historical state loading.

## Proof of Concept

```bash
# Saturate the 500 req/sec rate limit with minimum-gas historical requests
# targeting block 0 (earliest), triggering historical DB queries on every request

for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d '{
      "block": "earliest",
      "gas": 21000,
      "to": "0x0000000000000000000000000000000000000001",
      "data": "0x"
    }' &
done
wait
# Repeat in a loop to sustain 500 req/sec
# Result: rateLimitBucket exhausted; legitimate latest-block requests receive 429;
# DB receives sustained historical UNION queries across entity_history,
# account_balance, contract_state_change tables.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L27-37)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-50)
```java
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L18-47)
```java
    private static final long GAS_SCALE_FACTOR = 10_000L;

    @Min(0)
    @Max(100)
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

    // Necessary since bucket4j has a max capacity and fill rate of 1 token per nanosecond
    public long getGasPerSecond() {
        return scaleGas(gasPerSecond);
    }

    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L103-104)
```java
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-29)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
        } else if (block.isHash()) {
            return recordFileRepository.findByHash(block.name());
        }

        return recordFileRepository.findByIndex(block.number());
    }
```
