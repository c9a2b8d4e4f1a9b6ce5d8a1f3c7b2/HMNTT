### Title
Unprivileged Sender Impersonation of System Accounts via Long-Zero Address in `getSenderAccountIDAsNum()`

### Summary
In `TransactionExecutionService.getSenderAccountIDAsNum()`, when the supplied sender address satisfies `ConversionUtils.isLongZero()`, the alias-existence check is entirely skipped and an `AccountID` is constructed directly from the address bytes. For any account number in the range 1–999, `AccountReadableKVState.getDummySystemAccountIfApplicable()` synthesizes a valid dummy `Account` object regardless of whether that entity exists in the mirror node database. This allows any unauthenticated caller of `ContractExecutionService.processCall()` to impersonate system accounts (including the treasury, fee-collection account, etc.) as the EVM `msg.sender` in `eth_call` / `eth_estimateGas` simulations.

### Finding Description

**Code path:**

`ContractExecutionService.processCall()` → `callContract()` / `estimateGas()` → `TransactionExecutionService.execute()` → `defaultTransactionBodyBuilder()` → `getSenderAccountID()` → `getSenderAccountIDAsNum()`

**Root cause — `getSenderAccountIDAsNum()` (lines 267–285, `TransactionExecutionService.java`):**

```java
if (senderAddress != null && !ConversionUtils.isLongZero(senderAddress)) {
    // alias path: alias MUST exist in DB or PAYER_ACCOUNT_NOT_FOUND is thrown
    accountIDNum = aliasesReadableKVState.get(convertAddressToProtoBytes(senderAddress));
    if (accountIDNum == null) {
        throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
    }
} else {
    // long-zero path: NO existence check — AccountID is constructed directly
    final var senderAccountID = accountIdFromEvmAddress(senderAddress);
    accountIDNum = AccountID.newBuilder()
            .accountNum(senderAccountID.getAccountNum())
            ...
            .build();
}
```

For a non-long-zero address the alias lookup enforces existence. For a long-zero address the code unconditionally constructs the `AccountID`.

**Why the downstream null-check does not save it — `getSenderAccountID()` (lines 247–264):**

```java
final var account = accountReadableKVState.get(accountIDNum);
if (account == null) {
    throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
}
```

`accountReadableKVState.get()` calls `AccountReadableKVState.readFromDataSource()`, which falls through to `getDummySystemAccountIfApplicable()` (lines 103–113):

```java
private Optional<Account> getDummySystemAccountIfApplicable(AccountID accountID) {
    if (accountID != null && accountID.hasAccountNum()) {
        final var accountNum = accountID.accountNum();
        return AccountDetector.isStrictSystem(accountNum) && accountNum != 0
                ? Optional.of(Account.newBuilder()
                        .accountId(accountID)
                        .key(getDefaultKey())
                        .build())
                : Optional.empty();
    }
    return Optional.empty();
}
```

`AccountDetector.isStrictSystem()` returns `true` for any `accountNum` in `[1, 999]`. A synthetic `Account` with `DEFAULT_KEY` is returned, so `account == null` is never true, and the null-guard is bypassed.

**Exploit flow:**
1. Attacker sends `eth_call` with `from = 0x0000000000000000000000000000000000000002` (treasury, account 2).
2. `ConversionUtils.isLongZero()` → `true`; alias lookup skipped.
3. `AccountID{accountNum=2}` constructed directly.
4. `getDummySystemAccountIfApplicable()` synthesizes a valid `Account` (key present, not a smart contract).
5. `getSenderAccountID()` returns `AccountID{accountNum=2}`.
6. The simulated transaction runs with treasury as `msg.sender` / payer.

### Impact Explanation
An attacker can simulate EVM calls (`eth_call`, `eth_estimateGas`) as any Hedera system account (accounts 1–999, including treasury 0.0.2, fee-collection account, staking-reward account, etc.) without owning or controlling those accounts. Concrete consequences:

- **Balance-check bypass in simulation**: If the real treasury record exists in the mirror DB, the simulation uses its actual large balance, allowing the attacker to simulate high-value transfers that would fail for their real account.
- **Triggering privileged contract branches**: Contracts that gate logic on `msg.sender == address(0x2)` (treasury) or other system addresses will execute those branches in the simulation, leaking information about privileged code paths.
- **Incorrect gas estimates**: Gas estimates produced under a system-account identity may differ materially from what the attacker's real account would consume, misleading DApps.

Severity: **Medium**. No real funds can be moved (mirror node is read-only simulation), but simulation integrity is broken and privileged contract logic is exposed.

### Likelihood Explanation
Exploitation requires zero privileges: any caller of the public `eth_call` / `eth_estimateGas` JSON-RPC endpoint can supply an arbitrary `from` value. Crafting a long-zero address is trivial (pad a system account number to 20 bytes). The attack is repeatable, stateless, and requires no prior knowledge beyond the system account numbering scheme (publicly documented).

### Recommendation
In the `else` branch of `getSenderAccountIDAsNum()` (the long-zero path), add an explicit database existence check before accepting the constructed `AccountID` as a valid sender, mirroring the enforcement already applied to alias addresses:

```java
} else {
    final var senderAccountID = accountIdFromEvmAddress(senderAddress);
    accountIDNum = AccountID.newBuilder()
            .accountNum(senderAccountID.getAccountNum())
            .shardNum(senderAccountID.getShardNum())
            .realmNum(senderAccountID.getRealmNum())
            .build();
    // ADD: verify the account actually exists in the DB
    final var timestamp = ContractCallContext.get().getTimestamp();
    if (commonEntityAccessor.get(accountIDNum, timestamp).isEmpty()) {
        throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
    }
}
```

This ensures that long-zero addresses for non-existent (including synthetic system) accounts are rejected with `PAYER_ACCOUNT_NOT_FOUND`, consistent with the alias path.

### Proof of Concept

**Precondition**: Mirror node `eth_call` endpoint is accessible (no authentication).

**Step 1** — Craft a long-zero address for the treasury (account 0.0.2):
```
from = 0x0000000000000000000000000000000000000002
```

**Step 2** — Send an `eth_call` request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [{
    "from": "0x0000000000000000000000000000000000000002",
    "to":   "<target_contract_address>",
    "data": "<calldata_for_privileged_function>"
  }, "latest"],
  "id": 1
}
```

**Step 3** — Observe that:
- The call succeeds (no `PAYER_ACCOUNT_NOT_FOUND` error).
- `msg.sender` inside the EVM is `0x0000000000000000000000000000000000000002` (treasury).
- Any contract branch gated on `msg.sender == address(0x2)` executes.

**Step 4** — Repeat with any account number 1–999 (e.g., `0x0000000000000000000000000000000000000320` for account 800, the staking-reward account) to confirm the full system-account range is reachable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L239-265)
```java
    private AccountID getSenderAccountID(final CallServiceParameters params) {
        // Set a default account to keep the sender parameter optional.
        if (params.getSender().isZero() && params.getValue() == 0L) {
            return EntityIdUtils.toAccountId(systemEntity.treasuryAccount());
        }
        final var senderAddress = params.getSender();
        final var accountIDNum = getSenderAccountIDAsNum(senderAddress);

        final var account = accountReadableKVState.get(accountIDNum);
        if (account == null) {
            throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
        } else if (account.smartContract()) {
            return EntityIdUtils.toAccountId(systemEntity.treasuryAccount());
        } else if (!account.hasKey() || account.key().equals(IMMUTABILITY_SENTINEL_KEY)) {
            // If the account is hollow, complete it in the state as a workaround
            // as this happens in HandleWorkflow in hedera-app but calling the
            // transaction executor directly skips this account completion and
            // this results in failed transactions that would otherwise succeed
            // against the consensus node.
            final var writableAccountCache =
                    ContractCallContext.get().getWriteCacheState(AccountReadableKVState.STATE_ID);
            final var completedAccount = account.copyBuilder().key(DEFAULT_KEY).build();
            writableAccountCache.put(account.accountId(), completedAccount);
        }

        return accountIDNum;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L267-285)
```java
    private AccountID getSenderAccountIDAsNum(final Address senderAddress) {
        AccountID accountIDNum;
        if (senderAddress != null && !ConversionUtils.isLongZero(senderAddress)) {
            // If the address is an alias we need to first check if it exists and get the AccountID as a num.
            accountIDNum = aliasesReadableKVState.get(convertAddressToProtoBytes(senderAddress));
            if (accountIDNum == null) {
                throwPayerAccountNotFoundException(SENDER_NOT_FOUND);
            }
        } else {
            final var senderAccountID = accountIdFromEvmAddress(senderAddress);
            // If the address was passed as a long-zero address we need to convert it to the correct AccountID type.
            accountIDNum = AccountID.newBuilder()
                    .accountNum(senderAccountID.getAccountNum())
                    .shardNum(senderAccountID.getShardNum())
                    .realmNum(senderAccountID.getRealmNum())
                    .build();
        }
        return accountIDNum;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AccountReadableKVState.java (L103-113)
```java
    private Optional<Account> getDummySystemAccountIfApplicable(AccountID accountID) {
        if (accountID != null && accountID.hasAccountNum()) {
            final var accountNum = accountID.accountNum();
            return AccountDetector.isStrictSystem(accountNum) && accountNum != 0
                    ? Optional.of(Account.newBuilder()
                            .accountId(accountID)
                            .key(getDefaultKey())
                            .build())
                    : Optional.empty();
        }
        return Optional.empty();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/utils/AccountDetector.java (L9-13)
```java
    private static final int SYSTEM_ACCOUNT_BOUNDARY = 750;
    private static final int STRICT_SYSTEM_ACCOUNT_BOUNDARY = 999;

    public static boolean isStrictSystem(long accountNum) {
        return accountNum >= 0 && accountNum <= STRICT_SYSTEM_ACCOUNT_BOUNDARY;
```
