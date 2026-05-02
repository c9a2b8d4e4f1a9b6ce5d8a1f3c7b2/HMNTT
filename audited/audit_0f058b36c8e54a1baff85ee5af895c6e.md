### Title
Internal `consensusTimestamp` Disclosure via Mismatched Hash/Result Lookup in `getContractOpcodes()`

### Summary
When an unprivileged user supplies a transaction hash that exists in `contract_transaction_hash` but has no matching row in `contract_result`, `OpcodeServiceImpl` throws an `EntityNotFoundException` whose message embeds the raw internal nanosecond `consensusTimestamp`. The web3 `GenericControllerAdvice` unconditionally forwards the exception message to the HTTP response body for all non-5xx status codes, so the timestamp is returned verbatim to the caller.

### Finding Description

**Code path:**

1. `OpcodesController.getContractOpcodes()` accepts any transaction hash from an unauthenticated caller and delegates to `OpcodeServiceImpl.processOpcodeCall()`. [1](#0-0) 

2. Inside `buildCallServiceParameters()`, when a `TransactionHashParameter` is provided, the code looks up `contractTransactionHashRepository.findByHash(...)` and, if found, extracts `consensusTimestamp` from the result. [2](#0-1) 

3. That timestamp is then passed to the overloaded `buildCallServiceParameters(Long, Transaction, EthereumTransaction)`, which calls `contractResultRepository.findById(consensusTimestamp)`. If no row exists, it throws:
   ```
   new EntityNotFoundException("Contract result not found: " + consensusTimestamp)
   ``` [3](#0-2) 

4. `GenericControllerAdvice.handleExceptionInternal()` sets `detail = ex.getMessage()` for all non-5xx responses (404 is not 5xx), so the full message — including the raw nanosecond timestamp — is serialised into the JSON response body. [4](#0-3) 

**Root cause / failed assumption:** The code assumes that every hash in `contract_transaction_hash` has a corresponding row in `contract_result`. The database schema explicitly allows orphaned rows: the migration inserts ethereum-transaction hashes into `contract_transaction_hash` only when *no* matching `contract_result` row exists. [5](#0-4) 

The existing test confirms the message is returned to callers: [6](#0-5) 

### Impact Explanation
The leaked value is the nanosecond-precision consensus timestamp used as the primary key across multiple partitioned tables (`contract_result`, `contract_state_change`, `contract_log`, etc.). Knowing it allows an attacker to:
- Correlate otherwise-unlinkable transactions across tables using direct primary-key queries.
- Enumerate the precise ordering and timing of historical contract executions, revealing internal ledger structure that is not intended to be exposed through this API.
- Use the timestamp as a stepping stone to probe related records in other endpoints that accept a `consensusTimestamp` parameter.

Severity is **Low–Medium** (information disclosure; no direct fund manipulation).

### Likelihood Explanation
The precondition — a hash present in `contract_transaction_hash` but absent from `contract_result` — is a normal, documented database state for ethereum transactions without a contract result. No privileges, no special account, and no prior knowledge beyond a valid transaction hash are required. The endpoint is publicly reachable and the trigger is fully deterministic and repeatable.

### Recommendation
1. **Sanitise the exception message**: Do not embed the raw `consensusTimestamp` in the user-visible error. Replace:
   ```java
   new EntityNotFoundException("Contract result not found: " + consensusTimestamp)
   ```
   with a generic message such as `"Contract result not found"`, logging the timestamp server-side only.

2. **Alternatively**, extend `GenericControllerAdvice.handleExceptionInternal()` to strip the `detail` field for all 404 responses originating from `EntityNotFoundException`, consistent with how 5xx details are already suppressed. [4](#0-3) 

### Proof of Concept

**Precondition:** Identify (or insert in a test environment) a hash `H` that exists in `contract_transaction_hash` with `consensus_timestamp = T` but has no row in `contract_result` at `T`. This is a naturally occurring state for ethereum transactions without a contract result.

**Steps:**
```
GET /api/v1/contracts/results/0x<H>/opcodes?stack=true
Accept-Encoding: gzip
```

**Expected response (HTTP 404):**
```json
{
  "message": "Not Found",
  "detail": "Contract result not found: <T>"
}
```

Where `<T>` is the raw nanosecond `consensusTimestamp` internal database key, confirming the information disclosure.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-65)
```java
    @GetMapping(value = "/{transactionIdOrHash}/opcodes")
    OpcodesResponse getContractOpcodes(
            @PathVariable TransactionIdOrHashParameter transactionIdOrHash,
            @RequestParam(required = false, defaultValue = "true") boolean stack,
            @RequestParam(required = false, defaultValue = "false") boolean memory,
            @RequestParam(required = false, defaultValue = "false") boolean storage,
            @RequestHeader(value = HttpHeaders.ACCEPT_ENCODING) String acceptEncoding) {
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L83-94)
```java
            case TransactionHashParameter transactionHash -> {
                ContractTransactionHash contractTransactionHash = contractTransactionHashRepository
                        .findByHash(transactionHash.hash().toArray())
                        .orElseThrow(() ->
                                new EntityNotFoundException("Contract transaction hash not found: " + transactionHash));

                transaction = null;
                consensusTimestamp = contractTransactionHash.getConsensusTimestamp();
                ethereumTransaction = ethereumTransactionRepository
                        .findByConsensusTimestampAndPayerAccountId(
                                consensusTimestamp, EntityId.of(contractTransactionHash.getPayerAccountId()))
                        .orElse(null);
```

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

**File:** importer/src/main/resources/db/migration/v1/V1.89.0.1__add_contract_lookup_tables.sql (L15-19)
```sql
insert into contract_transaction_hash(consensus_timestamp,hash,payer_account_id,entity_id, transaction_result)
    (select et.consensus_timestamp, et.hash, et.payer_account_id, t.payer_account_id, t.result
     from ethereum_transaction et
     join transaction t on t.consensus_timestamp = et.consensus_timestamp
     where not exists (select 1 from contract_result cr where cr.consensus_timestamp = et.consensus_timestamp));
```

**File:** web3/src/test/java/org/hiero/mirror/web3/controller/OpcodesControllerTest.java (L396-406)
```java
    void callWithContractResultNotFoundExceptionTest(final TransactionProviderEnum providerEnum) throws Exception {
        final TransactionIdOrHashParameter transactionIdOrHash = setUp(providerEnum);
        final var id = providerEnum.getContractResult().get().getConsensusTimestamp();

        when(contractResultRepository.findById(anyLong())).thenReturn(Optional.empty());

        mockMvc.perform(opcodesRequest(transactionIdOrHash))
                .andExpect(status().isNotFound())
                .andExpect(responseBody(
                        new GenericErrorResponse(NOT_FOUND.getReasonPhrase(), "Contract result not found: " + id)));
    }
```
