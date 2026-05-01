### Title
Internal `consensusTimestamp` Leaked in 404 Error Response via `getContractOpcodes`

### Summary
When a caller supplies a transaction hash that resolves in `contractTransactionHashRepository` but has no matching row in `contractResultRepository`, `OpcodeServiceImpl` throws `EntityNotFoundException` with the raw nanosecond `consensusTimestamp` embedded in the message. The web3 `GenericControllerAdvice` unconditionally forwards the exception message to the HTTP client for all non-5xx responses, so the internal timestamp is returned verbatim in the JSON error body.

### Finding Description
**Exact code path:**

`OpcodeServiceImpl.java` lines 154–156 — after resolving a `TransactionHashParameter` to a `consensusTimestamp` via `contractTransactionHashRepository.findByHash()`, the service calls:

```java
final var contractResult = contractResultRepository
    .findById(consensusTimestamp)
    .orElseThrow(() -> new EntityNotFoundException("Contract result not found: " + consensusTimestamp));
``` [1](#0-0) 

The raw `Long consensusTimestamp` (nanosecond-precision epoch value) is concatenated directly into the exception message.

`GenericControllerAdvice.java` lines 163–170 — the `notFoundException` handler (line 115) delegates to `handleExceptionInternal` with `NOT_FOUND` (HTTP 404). Inside `handleExceptionInternal`:

```java
var detail = !statusCode.is5xxServerError() ? ex.getMessage() : StringUtils.EMPTY;
var genericErrorResponse = new GenericErrorResponse(message, detail, StringUtils.EMPTY);
``` [2](#0-1) 

Because 404 is not a 5xx status, `detail` is set to the full exception message — including the timestamp — and serialised into the response body.

**Root cause:** The error-suppression guard (`!statusCode.is5xxServerError()`) only redacts server-error messages. Client-error (4xx) messages, including those that embed internal database keys, are passed through unchanged.

**Exploit flow:**
1. Attacker submits `GET /api/v1/contracts/results/{hash}/opcodes` with `Accept-Encoding: gzip` and a valid Ethereum transaction hash that exists in `contract_transaction_hash` but whose corresponding row in `contract_result` is absent (e.g., due to pruning, partial ingestion failure, or a migration gap).
2. `contractTransactionHashRepository.findByHash()` succeeds and returns the `ContractTransactionHash` record, including its `consensusTimestamp`.
3. `contractResultRepository.findById(consensusTimestamp)` returns empty.
4. `EntityNotFoundException("Contract result not found: " + consensusTimestamp)` is thrown.
5. `GenericControllerAdvice` returns HTTP 404 with body:
   ```json
   {"_status":{"messages":[{"message":"Not Found","detail":"Contract result not found: 1700000000123456789","data":""}]}}
   ```
6. The attacker now knows the exact nanosecond consensus timestamp for that hash.

**The test at `OpcodesControllerTest.java` lines 404–405 explicitly asserts this behaviour:**
```java
.andExpect(responseBody(
    new GenericErrorResponse(NOT_FOUND.getReasonPhrase(), "Contract result not found: " + id)));
``` [3](#0-2) 

### Impact Explanation
The `consensusTimestamp` is an internal nanosecond-precision key used to index transactions, contract results, record files, and related entities across the mirror-node database. Exposing it allows an attacker to:
- Correlate a known transaction hash to its exact consensus timestamp without going through the public Hedera mirror REST API.
- Use the timestamp as a seed to probe adjacent timestamps (±nanoseconds) against other endpoints that accept timestamp parameters, enabling low-cost transaction enumeration.
- Confirm the existence of a transaction in `contract_transaction_hash` even when it has been pruned from `contract_result`, leaking information about the node's data-retention state.

Severity is low-to-medium: no funds are directly at risk, but the disclosure violates the principle of not exposing internal database keys and enables enumeration attacks.

### Likelihood Explanation
The precondition (hash present in `contract_transaction_hash`, absent in `contract_result`) can arise from:
- Routine pruning: `contract_result` rows are pruned independently of `contract_transaction_hash` rows.
- Partial ingestion failures during high-load periods.
- Any attacker who can observe the pruning schedule can deliberately time requests to hit this window.

No authentication is required; the endpoint is public. The `Accept-Encoding: gzip` header is the only gate, and it is trivially satisfied. The attack is repeatable and requires no special privileges.

### Recommendation
1. **Remove the internal key from the error message.** Replace:
   ```java
   new EntityNotFoundException("Contract result not found: " + consensusTimestamp)
   ```
   with a message that does not embed the timestamp, e.g.:
   ```java
   new EntityNotFoundException("Contract result not found for the given transaction")
   ``` [4](#0-3) 

2. **Harden the error handler** in `GenericControllerAdvice.handleExceptionInternal` to sanitise 4xx detail messages that may contain internal identifiers, or adopt an allowlist of safe message patterns. [5](#0-4) 

3. Update `callWithContractResultNotFoundExceptionTest` to assert that the response body does **not** contain the raw timestamp.

### Proof of Concept
```
# Step 1 – find a hash present in contract_transaction_hash but pruned from contract_result
# (or wait for a pruning cycle; or use a known partially-ingested hash)

HASH=0xaabbcc...  # valid hash with missing contract_result row

# Step 2 – call the opcodes endpoint
curl -s -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/${HASH}/opcodes" | gunzip

# Step 3 – observe response
# {"_status":{"messages":[{"message":"Not Found",
#   "detail":"Contract result not found: 1700000000123456789","data":""}]}}
#
# The value 1700000000123456789 is the internal consensusTimestamp (nanoseconds since epoch).
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L154-156)
```java
        final var contractResult = contractResultRepository
                .findById(consensusTimestamp)
                .orElseThrow(() -> new EntityNotFoundException("Contract result not found: " + consensusTimestamp));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L163-170)
```java
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex, @Nullable Object body, HttpHeaders headers, HttpStatusCode statusCode, WebRequest request) {
        var message = statusCode instanceof HttpStatus hs ? hs.getReasonPhrase() : statusCode.toString();
        var detail = !statusCode.is5xxServerError() ? ex.getMessage() : StringUtils.EMPTY; // Don't leak server errors
        var genericErrorResponse = new GenericErrorResponse(message, detail, StringUtils.EMPTY);
        request.setAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, ex, SCOPE_REQUEST);
        return new ResponseEntity<>(genericErrorResponse, headers, statusCode);
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/controller/OpcodesControllerTest.java (L404-405)
```java
                .andExpect(responseBody(
                        new GenericErrorResponse(NOT_FOUND.getReasonPhrase(), "Contract result not found: " + id)));
```
