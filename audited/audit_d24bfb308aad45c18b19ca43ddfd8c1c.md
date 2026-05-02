### Title
Unvalidated User-Supplied `node_account_id` in `ConstructionPayloads` Bypasses Configured Node Whitelist

### Summary
The `/construction/payloads` endpoint accepts a client-controlled `node_account_id` metadata value and embeds it directly into the unsigned transaction without validating it against the server's configured node list. Any unprivileged caller can substitute an arbitrary syntactically-valid account ID between the `/construction/metadata` and `/construction/payloads` steps, causing the resulting transaction to target a node outside the operator's trusted set — including decommissioned or non-record-exporting nodes — leading to a transaction that is submitted but never appears in the mirror node's records.

### Finding Description

**Code path:**

`ConstructionMetadata` (line 166) correctly selects a node account ID exclusively from the server's configured network:

```go
nodeAccountId, rErr := c.getRandomNodeAccountId()   // iterates c.sdkClient.GetNetwork()
``` [1](#0-0) 

That value is returned to the client in the metadata response. The client then passes metadata (possibly modified) to `/construction/payloads`. `ConstructionPayloads` calls `getTransactionNodeAccountId` to recover the node account ID:

```go
nodeAccountId, rErr := c.getTransactionNodeAccountId(request.Metadata)
``` [2](#0-1) 

`getTransactionNodeAccountId` performs **only syntactic parsing** — it never checks whether the parsed ID is present in `c.sdkClient.GetNetwork()`:

```go
nodeAccountId, err := hiero.AccountIDFromString(str)   // format check only
if err != nil { return emptyAccountId, errors.ErrInvalidAccount }
return nodeAccountId, nilErr                           // no whitelist check
``` [3](#0-2) 

The unvalidated ID is then embedded into the transaction by `transactionSetNodeAccountId`, which also performs no validation:

```go
func transactionSetNodeAccountId(nodeAccountId hiero.AccountID) updater {
    return func(transaction hiero.TransactionInterface) *rTypes.Error {
        if _, err := hiero.TransactionSetNodeAccountIDs(transaction, []hiero.AccountID{nodeAccountId}); err != nil {
``` [4](#0-3) 

At submission time, `ConstructionSubmit` executes the transaction using the embedded node account ID:

```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
``` [5](#0-4) 

**Root cause:** The server generates a safe node account ID in `/construction/metadata` but then unconditionally trusts the client to return it unmodified in `/construction/payloads`. There is no server-side enforcement that the `node_account_id` in the payloads request belongs to the set returned by `c.sdkClient.GetNetwork()`.

**Failed assumption:** The design assumes the client will faithfully relay the metadata from `/construction/metadata` to `/construction/payloads`. The Rosetta Construction API places no cryptographic or session binding on metadata between steps, so this assumption is trivially violated.

### Impact Explanation

If an attacker supplies the account ID of a node that is reachable but decommissioned (still accepting connections but no longer submitting records to the mirror node), `ConstructionSubmit` will succeed (the SDK finds the node address in the address book), the transaction will be processed by the network, but the mirror node will never receive the corresponding record. From the mirror node's perspective the transaction is permanently missing, breaking the integrity guarantee that all submitted transactions are observable. This is a medium-severity integrity issue: it does not allow theft of funds, but it allows an attacker to make their own (or a victim's) transaction invisible to any downstream system that relies on the mirror node for finality confirmation.

### Likelihood Explanation

The precondition — a node account ID that is syntactically valid, reachable at the network level, but not exporting records — is an unusual but realistic network state during node rotation or decommissioning events. No privilege is required; any caller of the public Rosetta API can perform this attack. The modification is trivial (change one string field in the JSON body). The attack is repeatable for every transaction submitted through the service during the window when such a node exists.

### Recommendation

In `getTransactionNodeAccountId`, after parsing the account ID, validate it against the server's configured node set:

```go
knownNodes := c.sdkClient.GetNetwork()
found := false
for _, id := range knownNodes {
    if id == nodeAccountId {
        found = true
        break
    }
}
if !found {
    log.Errorf("Node account id %s is not in the configured node list", str)
    return emptyAccountId, errors.ErrInvalidAccount
}
```

This mirrors the logic already present in `getRandomNodeAccountId` and ensures the client cannot steer transactions to nodes outside the operator's trusted set. [6](#0-5) 

### Proof of Concept

1. Call `POST /construction/metadata` with a valid `operation_type`. Note the returned `node_account_id` (e.g., `0.0.3`).
2. Call `POST /construction/payloads` with the same operations but replace `node_account_id` in the metadata with the account ID of a known decommissioned node (e.g., `0.0.9999`):
   ```json
   {
     "metadata": {
       "node_account_id": "0.0.9999",
       "valid_until_nanos": "<value from step 1>"
     },
     "operations": [...]
   }
   ```
3. The service returns an unsigned transaction with `nodeAccountIDs = [0.0.9999]` — no error is raised.
4. Sign the transaction and call `POST /construction/submit`.
5. If `0.0.9999` is reachable but not exporting records, the SDK submits successfully, the network processes the transaction, but the mirror node never records it.
6. Confirm by querying the mirror node REST API for the transaction hash — it returns 404.

### Citations

**File:** rosetta/app/services/construction_service.go (L165-170)
```go
	// node account id
	nodeAccountId, rErr := c.getRandomNodeAccountId()
	if rErr != nil {
		return nil, rErr
	}
	metadata[metadataKeyNodeAccountId] = nodeAccountId.String()
```

**File:** rosetta/app/services/construction_service.go (L222-225)
```go
	nodeAccountId, rErr := c.getTransactionNodeAccountId(request.Metadata)
	if rErr != nil {
		return nil, rErr
	}
```

**File:** rosetta/app/services/construction_service.go (L355-355)
```go
	_, err = hiero.TransactionExecute(transaction, c.sdkClient)
```

**File:** rosetta/app/services/construction_service.go (L383-390)
```go
	nodeAccountId, err := hiero.AccountIDFromString(str)
	if err != nil {
		log.Errorf("Invalid node account id provided in metadata: %s", str)
		return emptyAccountId, errors.ErrInvalidAccount
	}

	log.Infof("Use node account id %s from metadata", str)
	return nodeAccountId, nilErr
```

**File:** rosetta/app/services/construction_service.go (L511-538)
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

	if len(nodeAccountIds) == 0 {
		return hiero.AccountID{}, errors.ErrNodeAccountIdsEmpty
	}

	maxValue := big.NewInt(int64(len(nodeAccountIds)))
	index, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		log.Errorf("Failed to get a random number, use 0 instead: %s", err)
		return nodeAccountIds[0], nil
	}

	return nodeAccountIds[index.Int64()], nil
}
```

**File:** rosetta/app/services/construction_service.go (L717-724)
```go
func transactionSetNodeAccountId(nodeAccountId hiero.AccountID) updater {
	return func(transaction hiero.TransactionInterface) *rTypes.Error {
		if _, err := hiero.TransactionSetNodeAccountIDs(transaction, []hiero.AccountID{nodeAccountId}); err != nil {
			log.Errorf("Failed to set node account id for transaction: %s", err)
			return errors.ErrInternalServerError
		}
		return nil
	}
```
