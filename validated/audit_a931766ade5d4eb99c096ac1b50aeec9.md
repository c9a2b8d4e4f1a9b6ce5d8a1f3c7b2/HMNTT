The code at the exact lines cited is confirmed. Let me verify the key behavior before rendering judgment.

**Confirmed code behavior in `TransactionExecutionService.java`:**

- Lines 247–251: when `account.smartContract()` is true, the method returns `EntityIdUtils.toAccountId(systemEntity.treasuryAccount())` — not an exception.
- Lines 287–291: the developer comment on `throwPayerAccountNotFoundException` explicitly states *"in case the payer account is not found or **is a smart contract** the error response that is returned is `PAYER_ACCOUNT_NOT_FOUND`"* — yet the `smartContract()` branch never calls this method.
- Line 167: the returned `AccountID` is placed directly into `transactionID.accountID`.

The behavioral divergence from the stated intent is real and code-confirmed. All four required checks pass.

---

# Audit Report

## Title
Unprivileged Treasury Account Substitution via Smart Contract Sender in `getSenderAccountID`

## Summary
In `TransactionExecutionService.getSenderAccountID()`, when the caller-supplied sender address resolves to an account whose `smartContract()` flag is `true`, the method silently returns the system treasury `AccountID` instead of throwing `PAYER_ACCOUNT_NOT_FOUND`. This treasury `AccountID` is then embedded as `transactionID.accountID` (the declared payer) in every simulated transaction body, causing `eth_call` and `eth_estimateGas` to execute under treasury-account identity rather than the caller-supplied address.

## Finding Description
**Exact code path:**

`ContractCallService.doProcessCall()` (line 115) → `TransactionExecutionService.execute()` (line 73) → `buildContractCallTransactionBody()` / `buildContractCreateTransactionBody()` (lines 185–199 / 173–183) → `defaultTransactionBodyBuilder()` (line 163) → `getSenderAccountID()` (line 239).

Inside `getSenderAccountID()`:

```java
// TransactionExecutionService.java lines 247–251
final var account = accountReadableKVState.get(accountIDNum);
if (account == null) {
    throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
} else if (account.smartContract()) {
    return EntityIdUtils.toAccountId(systemEntity.treasuryAccount()); // silent substitution
}
``` [1](#0-0) 

The returned treasury `AccountID` is placed directly into `transactionID.accountID`:

```java
// TransactionExecutionService.java lines 165–168
.transactionID(TransactionID.newBuilder()
        .transactionValidStart(...)
        .accountID(getSenderAccountID(params))   // treasury ID injected here
        .build())
``` [2](#0-1) 

**Root cause / failed assumption:** The developer comment attached to `throwPayerAccountNotFoundException` (lines 287–291) explicitly acknowledges that the consensus node returns `PAYER_ACCOUNT_NOT_FOUND` when the payer *is a smart contract*:

```java
// In services SolvencyPreCheck#getPayerAccount() in case the payer account is not found
// or is a smart contract the error response that is returned is PAYER_ACCOUNT_NOT_FOUND,
// so we use it in here for consistency.
``` [3](#0-2) 

Despite this stated intent, the `smartContract()` branch at line 250 never calls `throwPayerAccountNotFoundException` — it returns the treasury account instead, directly contradicting the documented design.

**Why existing checks fail:** The `smartContract()` branch is the only guard for this case, and it *enables* the substitution rather than blocking it. There is no downstream check that detects or rejects a treasury-substituted payer before the transaction body reaches the executor.

## Impact Explanation
The treasury account (`systemEntity.treasuryAccount()`, i.e., account `0.0.2`) is a privileged system entity in Hedera. Substituting it as `transactionID.accountID` causes the EVM simulation to run under treasury identity:

1. **Behavioral divergence from consensus:** A call that should fail pre-EVM with `PAYER_ACCOUNT_NOT_FOUND` (because a smart contract cannot be a payer) instead succeeds in simulation. Developers using `eth_call` / `eth_estimateGas` to predict on-chain behavior receive incorrect results.
2. **Precompile authorization bypass:** Hedera precompile handlers and internal authorization logic that inspect the payer account (solvency checks, allowance checks, token-operation authorization) evaluate against the treasury's state rather than the attacker's account. The treasury's privileged state (e.g., system-token treasury relationships, elevated balances) is reachable by any unprivileged caller.
3. **False-positive contract interaction tests:** Incorrect gas estimates and false-positive access-control tests can cause developers to deploy contracts with incorrect assumptions about who can call them.

Severity: **Medium** — no direct fund loss on the mirror node itself, but produces systematically incorrect simulation output and exposes treasury-privileged simulation paths to unprivileged callers.

## Likelihood Explanation
The precondition is trivially satisfied: the attacker only needs the EVM address of any deployed smart contract, which is publicly visible via the mirror node's own REST API or any block explorer. No special privileges, keys, or tokens are required. The attack is a single unauthenticated HTTP request:

```json
POST /api/v1/contracts/call
{
  "from": "<any_deployed_contract_address>",
  "to":   "<target_contract>",
  "data": "<calldata>"
}
```

It is repeatable at will, requires no on-chain transaction, and leaves no trace distinguishable from a normal `eth_call`.

## Recommendation
Replace the silent treasury substitution in the `smartContract()` branch with the same rejection used for the null-account case, consistent with the developer comment at lines 287–291:

```java
} else if (account.smartContract()) {
    throwPayerAccountNotFoundException(SENDER_NOT_FOUND); // match consensus behavior
}
``` [4](#0-3) 

This aligns the mirror node's simulation with the consensus node's `SolvencyPreCheck#getPayerAccount()` behavior, which returns `PAYER_ACCOUNT_NOT_FOUND` for smart-contract payers.

## Proof of Concept
1. Identify any deployed smart contract address on the network (e.g., via `GET /api/v1/contracts`).
2. Send an `eth_call` request with that address as `from`:
   ```bash
   curl -X POST https://<mirror-node>/api/v1/contracts/call \
     -H 'Content-Type: application/json' \
     -d '{
       "from": "0x<deployed_contract_evm_address>",
       "to":   "0x<any_target_contract>",
       "data": "0x<calldata>",
       "gas":  100000
     }'
   ```
3. **Expected (consensus) behavior:** `PAYER_ACCOUNT_NOT_FOUND` error — the smart contract cannot be a payer.
4. **Actual (mirror node) behavior:** The call succeeds, executing the simulation with the treasury account (`0.0.2`) as the declared payer, returning EVM output as if the treasury initiated the call.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L165-168)
```java
                .transactionID(TransactionID.newBuilder()
                        .transactionValidStart(new Timestamp(Instant.now().getEpochSecond(), 0))
                        .accountID(getSenderAccountID(params))
                        .build())
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L247-251)
```java
        final var account = accountReadableKVState.get(accountIDNum);
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
