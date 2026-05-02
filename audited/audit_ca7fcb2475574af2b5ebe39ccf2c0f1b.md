### Title
Unvalidated User-Supplied `node_account_id` Bypasses Network Whitelist, Causing Guaranteed Submission Failure and SDK Error Leakage

### Summary
`getTransactionNodeAccountId()` accepts any syntactically valid `hiero.AccountID` string from client-supplied metadata without verifying it belongs to the server's known network. An unprivileged caller can supply an arbitrary account ID (e.g., `0.0.99999`) at the `/construction/payloads` step, which gets baked into the frozen transaction bytes. When that transaction is later submitted via `/construction/submit`, execution fails and the raw SDK error string — which may contain internal node addresses and routing details — is returned verbatim to the caller.

### Finding Description

**Step 1 — Metadata generation (server-side, correct path):**
`ConstructionMetadata` calls `getRandomNodeAccountId()`, which builds a whitelist exclusively from `c.sdkClient.GetNetwork()`: [1](#0-0) 

**Step 2 — Metadata consumption (client-controlled, broken path):**
`ConstructionPayloads` calls `getTransactionNodeAccountId(request.Metadata)`. That function only checks (a) key presence, (b) string type, and (c) syntactic validity via `hiero.AccountIDFromString`. There is **no membership check** against `c.sdkClient.GetNetwork()`: [2](#0-1) 

The attacker-controlled ID is then frozen into the transaction body: [3](#0-2) 

**Step 3 — Submission and error leakage:**
`ConstructionSubmit` executes the transaction. On failure the raw SDK error is attached to the response under the `"reason"` key with no sanitisation: [4](#0-3) 

The failed assumption is that `node_account_id` in the payloads request will always be the value the server placed in the metadata response. There is no enforcement of this.

### Impact Explanation
The Hiero Go SDK error string for an unreachable or unknown node typically includes the node's IP/port, gRPC status codes, and internal routing context. Returning `fmt.Sprintf("%s", err)` exposes this to any unauthenticated caller. Additionally, any transaction targeting a non-existent node will deterministically fail at submission, giving an attacker a reliable oracle to probe which node IDs the server considers valid vs. invalid (by comparing error messages). The `/construction/payloads` endpoint is publicly reachable in online mode with no authentication requirement. [5](#0-4) 

### Likelihood Explanation
Preconditions are minimal: the attacker only needs to be able to reach the Rosetta HTTP API (standard for any exchange integration). The full exploit requires only four sequential HTTP calls (preprocess → metadata → payloads → submit), all documented in the Rosetta spec. No credentials, no special network position, and no race condition are required. The attack is fully repeatable.

### Recommendation
After parsing the account ID in `getTransactionNodeAccountId`, validate it against the server's known network:

```go
nodeAccountId, err := hiero.AccountIDFromString(str)
if err != nil {
    return emptyAccountId, errors.ErrInvalidAccount
}

// Whitelist check — reject IDs not in the configured network
knownNetwork := c.sdkClient.GetNetwork()
valid := false
for _, knownId := range knownNetwork {
    if knownId == nodeAccountId {
        valid = true
        break
    }
}
if !valid {
    log.Errorf("Node account id %s not in known network", str)
    return emptyAccountId, errors.ErrInvalidAccount
}
```

Additionally, sanitise the SDK error before returning it — either strip it entirely or map it to a fixed internal message — to prevent internal topology leakage: [6](#0-5) 

### Proof of Concept

```
# 1. Preprocess (standard)
POST /construction/preprocess  { operations: [...] }

# 2. Metadata (standard — obtain valid metadata shape)
POST /construction/metadata  { options: { operation_type: "CRYPTOTRANSFER" } }

# 3. Payloads — inject non-existent node
POST /construction/payloads
{
  "metadata": {
    "node_account_id": "0.0.99999",   // <-- arbitrary, not in network
    "valid_start_nanos": "<value>",
    ...
  },
  "operations": [...]
}
# Returns unsigned_transaction with 0.0.99999 frozen as the node

# 4. Sign the unsigned_transaction (standard ed25519 signing)

# 5. Submit
POST /construction/submit  { signed_transaction: "<hex>" }

# Response:
{
  "code": 118,
  "message": "Transaction submission failed",
  "retriable": false,
  "details": {
    "reason": "<raw SDK error containing node address, gRPC status, routing details>"
  }
}
```

### Citations

**File:** rosetta/app/services/construction_service.go (L248-255)
```go
	if rErr = updateTransaction(
		transaction,
		transactionSetMemo(request.Metadata[types.MetadataKeyMemo]),
		transactionSetNodeAccountId(nodeAccountId),
		transactionSetTransactionId(payer, validStartNanos),
		transactionSetValidDuration(validDurationSeconds),
		transactionFreeze,
	); rErr != nil {
```

**File:** rosetta/app/services/construction_service.go (L355-362)
```go
	_, err = hiero.TransactionExecute(transaction, c.sdkClient)
	if err != nil {
		log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
		return nil, errors.AddErrorDetails(
			errors.ErrTransactionSubmissionFailed,
			"reason",
			fmt.Sprintf("%s", err),
		)
```

**File:** rosetta/app/services/construction_service.go (L370-391)
```go
func (c *constructionAPIService) getTransactionNodeAccountId(metadata map[string]any) (
	emptyAccountId hiero.AccountID, nilErr *rTypes.Error,
) {
	value, ok := metadata[metadataKeyNodeAccountId]
	if !ok {
		return emptyAccountId, errors.ErrMissingNodeAccountIdMetadata
	}

	str, ok := value.(string)
	if !ok {
		return emptyAccountId, errors.ErrInvalidArgument
	}

	nodeAccountId, err := hiero.AccountIDFromString(str)
	if err != nil {
		log.Errorf("Invalid node account id provided in metadata: %s", str)
		return emptyAccountId, errors.ErrInvalidAccount
	}

	log.Infof("Use node account id %s from metadata", str)
	return nodeAccountId, nilErr
}
```

**File:** rosetta/app/services/construction_service.go (L511-524)
```go
func (c *constructionAPIService) getRandomNodeAccountId() (hiero.AccountID, *rTypes.Error) {
	nodeAccountIds := make([]hiero.AccountID, 0)
	seen := map[hiero.AccountID]struct{}{}
	// network returned from sdkClient is a map[string]AccountID, the key is the address of a node and the value is
	// its node account id. Since a node can have multiple addresses, we need the seen map to get a unique node account
	// id array
	for _, nodeAccountId := range c.sdkClient.GetNetwork() {
		if _, ok := seen[nodeAccountId]; ok {
			continue
		}

		seen[nodeAccountId] = struct{}{}
		nodeAccountIds = append(nodeAccountIds, nodeAccountId)
	}
```

**File:** rosetta/app/errors/errors.go (L106-112)
```go
func AddErrorDetails(err *types.Error, key, description string) *types.Error {
	clone := *err
	clone.Details = make(map[string]any)
	maps.Copy(clone.Details, err.Details)
	clone.Details[key] = description
	return &clone
}
```
