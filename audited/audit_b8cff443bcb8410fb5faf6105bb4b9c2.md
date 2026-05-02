### Title
EIP-7702 Authorization Signatures Exposed for Failed Transactions, Enabling Replay

### Summary
`getContractResultsByTransactionIdOrHash()` returns the full `authorization_list` — including raw cryptographic signature components `r`, `s`, and `y_parity` — for every EIP-7702 (type-4) transaction regardless of whether the transaction succeeded or failed. When a transaction fails before the authorization is applied (e.g., the outer call reverts or runs out of gas after the authorization list is recorded on-chain), the signer's account nonce is not consumed, leaving the authorization signature valid and replayable by any observer of the mirror node API.

### Finding Description
**Exact code path:**

In `rest/viewmodel/contractResultDetailsViewModel.js`, the constructor computes `isTransactionSuccessful` at line 57–59 and uses it to gate `status` and `error_message`, but never uses it to gate `authorization_list`:

```js
// line 57-62 — isTransactionSuccessful IS computed
const isTransactionSuccessful = ContractResultDetailsViewModel._SUCCESS_PROTO_IDS.includes(
  contractResult.transactionResult
);
this.status = isTransactionSuccessful ? ... : ...;

// line 88-92 — authorization_list is set with NO check on isTransactionSuccessful
if (!isNil(ethTransaction)) {
  this.access_list = utils.toHexStringNonQuantity(ethTransaction.accessList);
  if (config.response.enableDelegationAddress) {
    this.authorization_list = ethTransaction.authorizationList?.map(
      (item) => new AuthorizationListItem(item)   // exposes r, s, y_parity unconditionally
    );
  }
```

`AuthorizationListItem` (`rest/model/authorizationListItem.js` lines 13–15) directly copies `r`, `s`, and `y_parity` from the DB row into the JSON response with no redaction.

The controller (`rest/controllers/contractController.js` lines 1187–1196) passes `contractResult` and `ethTransaction` straight into `setContractResultsResponse` → `ContractResultDetailsViewModel` with no pre-filtering on failure state.

**Root cause:** The failed-transaction guard (`isTransactionSuccessful`) is computed but never applied to the `authorization_list` field. The design assumption — that a failed transaction's authorization signatures are harmless to expose — is incorrect for EIP-7702.

**Exploit flow:**
1. Signer S signs an EIP-7702 authorization tuple `[chain_id, delegatee_addr, nonce=N, y_parity, r, s]` and hands it to a transaction submitter.
2. The submitter broadcasts a type-4 transaction that includes the authorization. The transaction is included in a block but the outer call reverts (e.g., the called contract throws, or gas runs out during execution after the authorization list is recorded).
3. In this failure scenario the authorization processing itself may not have incremented S's nonce (authorization nonce check failed, or the EVM reverted state including the nonce bump).
4. Attacker queries `GET /api/v1/contracts/results/{txHash}` — no authentication required.
5. Response contains `authorization_list[].r`, `.s`, `.y_parity` for the failed transaction.
6. Attacker constructs a new type-4 transaction reusing the exact same authorization tuple (same `chain_id`, `delegatee_addr`, `nonce=N`, `r`, `s`, `y_parity`) but with a different outer call — e.g., one that delegates S's account to an attacker-controlled contract.
7. If S's nonce is still N, the replayed authorization is accepted by the EVM, and S's account is delegated to the attacker's contract.

### Impact Explanation
EIP-7702 authorization signatures are the cryptographic proof that an EOA owner consents to delegate their account's code. Exposing `r`/`s`/`y_parity` for a failed transaction allows any unauthenticated API caller to extract a still-valid authorization and replay it in a new transaction context, potentially delegating the victim's EOA to a malicious contract. This gives the attacker full control over the victim's account for the duration of the delegation, enabling asset theft, arbitrary calls on behalf of the victim, and permanent account compromise if the delegated contract is designed to resist removal.

### Likelihood Explanation
No privileges are required — the endpoint is fully public. The attacker only needs to monitor the mirror node for type-4 transactions with non-null `error_message` and non-empty `authorization_list`. This is trivially scriptable. The window of opportunity exists as long as the signer's nonce has not advanced past the value embedded in the authorization tuple, which can persist indefinitely if the signer is inactive.

### Recommendation
Gate the `authorization_list` field on transaction success. In `ContractResultDetailsViewModel`, change:

```js
if (config.response.enableDelegationAddress) {
  this.authorization_list = ethTransaction.authorizationList?.map(...);
}
```

to:

```js
if (config.response.enableDelegationAddress && isTransactionSuccessful) {
  this.authorization_list = ethTransaction.authorizationList?.map(...);
}
```

Apply the same guard in `ContractResultViewModel` (line 30–32) where `authorization_list` is set from `contractResult.authorizationList` without any success check. For failed transactions, either omit the field entirely or return an empty array.

### Proof of Concept
1. Submit a type-4 (EIP-7702) Ethereum transaction on the network with a non-empty `authorization_list` that will revert (e.g., call a contract that always reverts).
2. Wait for the transaction to be indexed by the mirror node.
3. `curl https://<mirror-node>/api/v1/contracts/results/<txHash>`
4. Observe the response contains `"error_message": "<non-null>"` AND `"authorization_list": [{"r": "0x...", "s": "0x...", "y_parity": 1, ...}]`.
5. Verify the signer's on-chain nonce is still equal to the `nonce` field in the authorization tuple.
6. Construct a new type-4 transaction reusing the extracted `[chain_id, address, nonce, y_parity, r, s]` tuple but targeting a different (attacker-controlled) delegatee address — or the same tuple if the goal is to re-apply the original delegation.
7. Submit the new transaction; the EVM accepts the replayed authorization because the signer's nonce has not changed. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/viewmodel/contractResultDetailsViewModel.js (L57-62)
```javascript
    const isTransactionSuccessful = ContractResultDetailsViewModel._SUCCESS_PROTO_IDS.includes(
      contractResult.transactionResult
    );
    this.status = isTransactionSuccessful
      ? ContractResultDetailsViewModel._SUCCESS_RESULT
      : ContractResultDetailsViewModel._FAIL_RESULT;
```

**File:** rest/viewmodel/contractResultDetailsViewModel.js (L88-92)
```javascript
    if (!isNil(ethTransaction)) {
      this.access_list = utils.toHexStringNonQuantity(ethTransaction.accessList);
      if (config.response.enableDelegationAddress) {
        this.authorization_list = ethTransaction.authorizationList?.map((item) => new AuthorizationListItem(item));
      }
```

**File:** rest/model/authorizationListItem.js (L9-16)
```javascript
  constructor(authorizationListItem) {
    this.address = utils.toHexString(utils.stripHexPrefix(authorizationListItem.address), true, 40);
    this.chain_id = utils.toHexStringQuantity(utils.stripHexPrefix(authorizationListItem.chain_id));
    this.nonce = authorizationListItem.nonce;
    this.r = authorizationListItem.r;
    this.s = authorizationListItem.s;
    this.y_parity = authorizationListItem.y_parity;
  }
```

**File:** rest/viewmodel/contractResultViewModel.js (L30-32)
```javascript
    if (config.response.enableDelegationAddress && !isEmpty(contractResult.authorizationList)) {
      this.authorization_list = contractResult.authorizationList || [];
    }
```

**File:** rest/controllers/contractController.js (L1187-1196)
```javascript
    this.setContractResultsResponse(
      res,
      contractResult,
      recordFile,
      ethTransaction,
      contractLogs,
      contractStateChanges,
      fileData,
      convertToHbar
    );
```
