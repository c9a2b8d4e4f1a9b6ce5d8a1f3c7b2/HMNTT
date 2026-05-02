### Title
`FilterField.TO` Address Filter Bypass via Proxy Contract Intermediary

### Summary
The `ThrottleManagerImpl.throttle()` method evaluates `RequestProperties` filters solely against the top-level `to` field of the incoming `ContractCallRequest`. Because the EVM simulation fully executes internal calls (including `CALL`, `DELEGATECALL`, `STATICCALL`), an attacker can route a request through any proxy contract not listed in the filter, causing the `FilterField.TO EQUALS '<targetAddress>'` predicate to return `false` and skip the configured `REJECT` or `THROTTLE` action, while the EVM still reaches and executes the target contract.

### Finding Description

**Code path:**

`ContractController.call()` invokes `throttleManager.throttle(request)` before EVM execution: [1](#0-0) 

Inside `ThrottleManagerImpl.throttle()`, each configured `RequestProperties` is tested against the raw request object: [2](#0-1) 

`RequestFilter.test()` extracts the field value using the enum-bound extractor function: [3](#0-2) 

`FilterField.TO` is bound exclusively to `ContractCallRequest::getTo` — the literal string value from the HTTP request body: [4](#0-3) 

`ContractCallRequest.to` is a plain hex string field populated directly from the JSON body: [5](#0-4) 

**Root cause:** The filter evaluation happens entirely at the HTTP request layer, before EVM execution. It has no visibility into the internal call graph produced during simulation. The EVM simulation (`ContractExecutionService.processCall`) fully executes internal `CALL`/`DELEGATECALL`/`STATICCALL` opcodes: [6](#0-5) 

**Failed assumption:** The design assumes that the `to` field of the request is the only entry point to the target contract. This is false whenever a proxy contract exists on the network.

**Exploit flow:**
1. Admin configures: `field=TO, type=EQUALS, expression=0xTargetContract, action=REJECT`
2. Attacker identifies or deploys a proxy contract (`0xProxyContract`) with a passthrough function (e.g., `makeCallWithoutAmount(address _to, bytes _data)` — a pattern already present in the test suite): [7](#0-6) 
3. Attacker sends: `POST /api/v1/contracts/call` with `{ "to": "0xProxyContract", "data": "<encoded call to 0xTargetContract>" }`
4. `RequestFilter.test()` evaluates `"0xProxyContract".equalsIgnoreCase("0xTargetContract")` → `false` → no REJECT
5. EVM executes the proxy, which internally calls `0xTargetContract` — the simulation completes successfully

### Impact Explanation
Any `REJECT` or `THROTTLE` rule keyed on a specific contract address via `FilterField.TO` can be completely circumvented by any user who can identify or deploy a proxy contract. This undermines the operator's ability to block abusive or expensive simulations targeting specific contracts (e.g., HTS precompiles, high-cost system contracts). The attacker can also bypass per-contract rate limits (`THROTTLE` action), consuming mirror node resources at an uncontrolled rate. Severity is **Medium-High** because it directly defeats an explicit administrative security control.

### Likelihood Explanation
No privileges are required. The attacker only needs to know the target contract address and have access to any proxy contract on the network — a trivially low bar. The `EquivalenceContract` pattern (generic `call`/`delegatecall` forwarder) is a standard Solidity pattern. The bypass is deterministic and 100% repeatable. Any operator relying on `FilterField.TO` filters for access control is fully exposed.

### Recommendation
1. **Short-term:** Document that `FilterField.TO` filters only match the top-level request recipient and cannot block internal call targets. Operators must not rely on this filter alone for security-critical blocking.
2. **Long-term:** Implement post-execution call-trace inspection: after EVM simulation, walk the internal call graph and check whether any callee address matches a configured `TO` filter. If a match is found and the action is `REJECT`, return an error and discard the result. This requires hooking into the EVM tracer/operation tracer already available in the Besu-based execution layer.
3. Alternatively, maintain a blocklist checked inside the EVM's `CALL` opcode handler so that internal calls to blocked addresses are intercepted at execution time.

### Proof of Concept

**Precondition:** Mirror node configured with:
```yaml
hiero.mirror.web3.throttle.request:
  - filters:
      - field: TO
        type: EQUALS
        expression: "0x0000000000000000000000000000000000000167"  # HTS precompile
    action: REJECT
```

**Step 1 — Confirm direct call is blocked:**
```bash
curl -X POST http://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x0000000000000000000000000000000000000167","data":"0xdeadbeef","gas":100000}'
# Expected: 429 ThrottleException "Invalid request"
```

**Step 2 — Bypass via proxy:**
```bash
# 0xProxyContract is any deployed contract with:
# function forward(address _to, bytes calldata _data) external returns (bytes memory) {
#     (bool ok, bytes memory ret) = _to.call(_data);
#     return ret;
# }

curl -X POST http://mirror-node/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{
    "to":   "0xProxyContract",
    "data": "<ABI-encoded forward(0x0000000000000000000000000000000000000167, 0xdeadbeef)>",
    "gas":  500000
  }'
# Result: 200 OK — filter never triggered, HTS precompile was reached internally
```

The filter at `RequestFilter.test()` evaluates `"0xProxyContract".equalsIgnoreCase("0x...0167")` → `false`, so `action(requestFilter, request)` is never called, and the EVM proceeds to execute the internal call to the target. [8](#0-7)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L38-41)
```java
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L44-48)
```java
        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L66-76)
```java
    private void action(RequestProperties filter, ContractCallRequest request) {
        switch (filter.getAction()) {
            case LOG -> log.info("{}", request);
            case REJECT -> throw new ThrottleException("Invalid request");
            case THROTTLE -> {
                if (!filter.getBucket().tryConsume(1)) {
                    throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
                }
            }
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L31-35)
```java
    public boolean test(ContractCallRequest request) {
        var value = field.getExtractor().apply(request);
        var stringValue = value instanceof String s ? s : String.valueOf(value);
        return type.getPredicate().test(stringValue, expression);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/RequestFilter.java (L45-45)
```java
        TO(ContractCallRequest::getTo),
```

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/ContractCallRequest.java (L42-43)
```java
    @Hex(minLength = ADDRESS_LENGTH, maxLength = ADDRESS_LENGTH, allowEmpty = true)
    private String to;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractExecutionService.java (L44-67)
```java
    public String processCall(final ContractExecutionParameters params) {
        return ContractCallContext.run(ctx -> {
            var stopwatch = Stopwatch.createStarted();
            var stringResult = "";

            try {
                updateGasLimitMetric(params);

                Bytes result;
                if (params.isEstimate()) {
                    result = estimateGas(params, ctx);
                } else {
                    final var ethCallTxnResult = callContract(params, ctx);
                    result = Objects.requireNonNullElse(
                            Bytes.fromHexString(ethCallTxnResult.contractCallResult()), Bytes.EMPTY);
                }

                stringResult = result.toHexString();
            } finally {
                log.debug("Processed request {} in {}: {}", params, stopwatch, stringResult);
            }

            return stringResult;
        });
```

**File:** test/src/test/resources/solidity/contracts/EquivalenceContract.sol (L9-11)
```text
    function makeCallWithoutAmount(address _to, bytes memory _data) external returns (bool success, bytes memory returnData) {
        (success, returnData) = _to.call(_data);
    }
```
