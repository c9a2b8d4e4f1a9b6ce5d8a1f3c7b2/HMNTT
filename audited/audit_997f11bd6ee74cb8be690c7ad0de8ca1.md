### Title
Unauthenticated Opcode Trace Replay of Any Transaction Including Privileged System Transactions

### Summary
The `/api/v1/contracts/results/{transactionIdOrHash}/opcodes` endpoint in `OpcodesController` performs no authorization check on the supplied `TransactionIdParameter`. Any unprivileged caller who knows (or can discover) the payer account ID and valid-start timestamp of any contract transaction — including those executed by Hedera system accounts — can trigger a full EVM replay and receive the complete opcode trace, stack, memory, and storage of that transaction.

### Finding Description
**Code path:**

- `OpcodesController.java:52-68` — `getContractOpcodes()` accepts a `TransactionIdOrHashParameter` path variable. The only guards are: (1) `properties.isEnabled()` feature flag, (2) `Accept-Encoding: gzip` header presence, (3) `throttleManager.throttleOpcodeRequest()`. No authentication or ownership check exists.
- `OpcodeServiceImpl.java:96-114` — When the parameter is a `TransactionIdParameter`, the code calls `transactionRepository.findByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc(payerAccountId, validStartNs)` with the attacker-supplied values verbatim. There is no filter on transaction type, no check that the payer is the caller, and no check that the payer is not a system account.
- `TransactionIdParameter.java:17-41` — `valueOf()` parses any `shard.realm.num-seconds-nanos` string. It accepts system account IDs such as `0.0.2`, `0.0.50`, `0.0.800`, etc., without restriction.
- `OpcodeServiceImpl.java:152-175` — `buildCallServiceParameters()` then fetches the `ContractResult` for that consensus timestamp and builds full `ContractDebugParameters`, which are passed to `contractDebugService.processOpcodeCall()` for a complete EVM replay.

**Root cause:** The endpoint assumes that knowing a transaction ID is sufficient authorization to replay it. There is no concept of "this transaction belongs to you" or "this transaction is off-limits because it was executed by a privileged account."

**Exploit flow:**
1. Attacker queries the public mirror node REST API (`/api/v1/transactions?account.id=0.0.800&transactiontype=CONTRACTCALL`) to enumerate system-account contract transactions and obtain their transaction IDs.
2. Attacker constructs a `TransactionIdParameter` string, e.g., `0.0.800-1700000000-000000000`.
3. Attacker sends: `GET /api/v1/contracts/results/0.0.800-1700000000-000000000/opcodes?stack=true&memory=true&storage=true` with `Accept-Encoding: gzip`.
4. The service replays the transaction and returns the full opcode trace.

### Impact Explanation
The full opcode trace includes every EVM opcode executed, stack values at each step, memory contents, and storage slot reads/writes. For system contract calls (e.g., to Hedera system contracts at `0.0.359`, `0.0.360`, `0.0.800`), this can expose: internal contract state at the time of execution, function selectors and arguments passed by privileged accounts, return values, and intermediate storage values that are not otherwise surfaced by the standard REST API. This constitutes unauthorized information disclosure of privileged execution internals.

### Likelihood Explanation
The precondition is only that the feature flag `hiero.mirror.web3.opcode.tracer.enabled` is `true` (required for the endpoint to function at all, so any deployment where this is enabled is fully exposed). Transaction IDs of system accounts are publicly enumerable via the mirror node's own REST API. The attacker needs no credentials, no special network access, and no on-chain privileges. The attack is trivially repeatable for any historical contract transaction.

### Recommendation
1. **Authorization check on payer account:** Before replaying, verify that the requesting caller is authorized to inspect the transaction. At minimum, reject requests where the payer account ID falls within the system account range (e.g., `num <= 1000` on mainnet).
2. **Transaction type allowlist:** In `OpcodeServiceImpl.buildCallServiceParameters()`, after fetching the transaction, check `transaction.getType()` and reject non-user-initiated contract calls.
3. **API key / role-based access:** Gate the entire `/opcodes` endpoint behind an API key or role (e.g., Spring Security `@PreAuthorize`) so only authorized operators can use it, consistent with its intended use as a debugging tool.

### Proof of Concept
```
# Step 1: Discover a system-account contract transaction
curl "https://<mirror-node>/api/v1/transactions?account.id=0.0.800&transactiontype=CONTRACTCALL&limit=1"
# Response includes: "transaction_id": "0.0.800-1700000000-000000000"

# Step 2: Request full opcode trace as unprivileged user (no auth required)
curl -H "Accept-Encoding: gzip" \
  "https://<mirror-node>/api/v1/contracts/results/0.0.800-1700000000-000000000/opcodes?stack=true&memory=true&storage=true" \
  --compressed

# Result: Full JSON opcode trace including stack, memory, storage of the privileged transaction
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-68)
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

        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L96-114)
```java
            case TransactionIdParameter transactionId -> {
                final var validStartNs = convertToNanosMax(transactionId.validStart());
                final var payerAccountId = transactionId.payerAccountId();

                final var transactionList =
                        transactionRepository.findByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc(
                                payerAccountId, validStartNs);
                if (transactionList.isEmpty()) {
                    throw new EntityNotFoundException("Transaction not found: " + transactionId);
                }

                final var parentTransaction = transactionList.getFirst();
                transaction = parentTransaction;
                consensusTimestamp = parentTransaction.getConsensusTimestamp();
                ethereumTransaction = ethereumTransactionRepository
                        .findByConsensusTimestampAndPayerAccountId(
                                consensusTimestamp, parentTransaction.getPayerAccountId())
                        .orElse(null);
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L152-175)
```java
    private ContractDebugParameters buildCallServiceParameters(
            Long consensusTimestamp, Transaction transaction, EthereumTransaction ethTransaction) {
        final var contractResult = contractResultRepository
                .findById(consensusTimestamp)
                .orElseThrow(() -> new EntityNotFoundException("Contract result not found: " + consensusTimestamp));

        final var blockType = recordFileService
                .findByTimestamp(consensusTimestamp)
                .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
                .orElse(BlockType.LATEST);

        final var transactionType = transaction != null ? transaction.getType() : TransactionType.UNKNOWN.getProtoId();

        return ContractDebugParameters.builder()
                .block(blockType)
                .callData(getCallDataBytes(ethTransaction, contractResult))
                .ethereumData(getEthereumDataBytes(ethTransaction))
                .consensusTimestamp(consensusTimestamp)
                .gas(getGasLimit(ethTransaction, contractResult))
                .receiver(getReceiverAddress(ethTransaction, contractResult, transactionType))
                .sender(getSenderAddress(contractResult))
                .value(getValue(ethTransaction, contractResult).longValue())
                .build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/TransactionIdParameter.java (L17-41)
```java
    public static TransactionIdParameter valueOf(String transactionId) throws InvalidParametersException {
        if (transactionId == null) {
            return null;
        }

        Matcher matcher = TRANSACTION_ID_PATTERN.matcher(transactionId);
        if (!matcher.matches()) {
            return null;
        }

        try {
            long shard = Long.parseLong(matcher.group(1));
            long realm = Long.parseLong(matcher.group(2));
            long num = Long.parseLong(matcher.group(3));
            long seconds = Long.parseLong(matcher.group(4));
            int nanos = Integer.parseInt(matcher.group(5));

            EntityId entityId = EntityId.of(shard, realm, num);
            Instant validStart = Instant.ofEpochSecond(seconds, nanos);

            return new TransactionIdParameter(entityId, validStart);
        } catch (Exception e) {
            throw new InvalidParametersException(e.getMessage());
        }
    }
```
