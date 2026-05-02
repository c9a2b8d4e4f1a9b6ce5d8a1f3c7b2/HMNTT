The code at the exact lines cited is confirmed. Here is the audit result:

---

Audit Report

## Title
Silent Treasury Substitution for Smart Contract Sender in `getSenderAccountID()` Produces Incorrect Payer in Simulation Records

## Summary
When a caller supplies a `from` address that resolves to a smart contract account, `getSenderAccountID()` silently returns the treasury `AccountID` instead of throwing `PAYER_ACCOUNT_NOT_FOUND`. This directly contradicts the method's own explanatory comment and causes every simulation record produced by that call to carry the treasury account as the canonical payer.

## Finding Description
In `web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java`, `getSenderAccountID()` (lines 239–265) contains three branches after resolving the sender address:

- **Line 248–249**: `account == null` → correctly calls `throwPayerAccountNotFoundException()`
- **Line 250–251**: `account.smartContract()` → **incorrectly** returns `EntityIdUtils.toAccountId(systemEntity.treasuryAccount())`
- **Line 252–261**: hollow account → completes the account in writable state [1](#0-0) 

The comment at lines 287–290 explicitly documents the intended behavior:

> "In services `SolvencyPreCheck#getPayerAccount()` in case the payer account is not found **or is a smart contract** the error response that is returned is `PAYER_ACCOUNT_NOT_FOUND`, so we use it in here for consistency." [2](#0-1) 

The `smartContract()` branch is the only one that should also call `throwPayerAccountNotFoundException()` but instead silently substitutes the treasury. The returned `AccountID` is then embedded directly into the `TransactionID` of every `TransactionBody` variant built by `defaultTransactionBodyBuilder()`: [3](#0-2) 

This `TransactionID.accountID` is the canonical payer field in every `SingleTransactionRecord` produced by `executor.execute()`.

## Impact Explanation
1. **Incorrect records**: Every `SingleTransactionRecord` emitted for such a call records the treasury account as payer, not the supplied smart contract address. Downstream consumers (audit logs, analytics, block explorers) will attribute the simulated transaction to the treasury, masking the true origin.
2. **Divergent simulation results**: The treasury account may carry a different balance and permission state than the supplied smart contract address. Simulations that depend on payer balance (e.g., value-bearing `eth_call`) will produce results that diverge from what would actually happen on the consensus network, undermining the correctness guarantee of `eth_call` / `eth_estimateGas`.
3. **No error surfaced to caller**: The caller receives a successful simulation response with no indication that their `from` address was silently replaced, making the substitution invisible.

## Likelihood Explanation
No privileges are required. Any caller of the public JSON-RPC endpoints (`eth_call`, `eth_estimateGas`, `debug_traceTransaction`) can trigger this by setting `from` to any deployed smart contract address. Smart contract addresses are trivially discoverable from the mirror node's own REST API or any block explorer. The condition is deterministic and reproducible on every such request.

## Recommendation
Replace the silent treasury substitution in the `smartContract()` branch with the same exception that is thrown for a missing account:

```java
// Before (line 250–251):
} else if (account.smartContract()) {
    return EntityIdUtils.toAccountId(systemEntity.treasuryAccount());
}

// After:
} else if (account.smartContract()) {
    throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
}
```

This aligns the implementation with the documented intent at lines 287–290 and with the behavior of `SolvencyPreCheck#getPayerAccount()` on the consensus node. [4](#0-3) 

## Proof of Concept
1. Identify any deployed smart contract address `0xABCD…` (e.g., via the mirror node REST API `/api/v1/contracts`).
2. Issue an `eth_call` RPC request with `"from": "0xABCD…"` and any `"to"` / `"data"`.
3. `getSenderAccountID()` resolves the address, finds `account.smartContract() == true`, and returns the treasury `AccountID` without throwing.
4. `defaultTransactionBodyBuilder()` embeds the treasury account as `TransactionID.accountID`.
5. The resulting simulation record's payer is the treasury account, not `0xABCD…`.
6. If the call carries a non-zero `value`, the simulation uses the treasury's balance rather than the smart contract's balance, producing a result that may differ from actual on-chain execution.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L163-171)
```java
    private TransactionBody.Builder defaultTransactionBodyBuilder(final CallServiceParameters params) {
        return TransactionBody.newBuilder()
                .transactionID(TransactionID.newBuilder()
                        .transactionValidStart(new Timestamp(Instant.now().getEpochSecond(), 0))
                        .accountID(getSenderAccountID(params))
                        .build())
                .nodeAccountID(EntityIdUtils.toAccountId(systemEntity.treasuryAccount()))
                .transactionValidDuration(TRANSACTION_DURATION);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L248-251)
```java
        if (account == null) {
            throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
        } else if (account.smartContract()) {
            return EntityIdUtils.toAccountId(systemEntity.treasuryAccount());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L287-291)
```java
    // In services SolvencyPreCheck#getPayerAccount() in case the payer account is not found or is a smart contract the
    // error response that is returned is PAYER_ACCOUNT_NOT_FOUND, so we use it in here for consistency.
    private void throwPayerAccountNotFoundException(final String message) {
        throw new MirrorEvmTransactionException(PAYER_ACCOUNT_NOT_FOUND, message, StringUtils.EMPTY);
    }
```
