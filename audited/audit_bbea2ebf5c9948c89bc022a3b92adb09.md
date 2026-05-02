### Title
Unbounded `findByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc` Query Enables DB Resource Exhaustion via Opcode Endpoint

### Summary
`TransactionRepository.findByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc` issues an unbounded SQL query with no `LIMIT` clause, returning every transaction row sharing a given `(payerAccountId, validStartNs)` pair. `OpcodeServiceImpl.buildCallServiceParameters` fetches the full result set but discards all rows except `getFirst()`. Because the opcode endpoint's rate-limit bucket is a single global in-memory token (1 RPS, not per-IP), an attacker can monopolize that slot with maximally expensive queries, causing sustained unnecessary DB I/O and starving legitimate users of the endpoint.

### Finding Description

**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/repository/TransactionRepository.java`, lines 14–15:
```java
List<Transaction> findByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc(
        EntityId payerAccountId, long validStartNs);
```
Spring Data JPA derives `SELECT * FROM transaction WHERE payer_account_id = ? AND valid_start_ns = ? ORDER BY consensus_timestamp ASC` with **no LIMIT**.

`web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java`, lines 100–107:
```java
final var transactionList =
        transactionRepository.findByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc(
                payerAccountId, validStartNs);
if (transactionList.isEmpty()) {
    throw new EntityNotFoundException(...);
}
final var parentTransaction = transactionList.getFirst();   // only first row used
```
All rows beyond the first are fetched from the DB, transferred over the JDBC connection, deserialized into `Transaction` objects, and then immediately garbage-collected.

**Root cause / failed assumption:** The design assumes the result set is small (typically 1 parent + a handful of children). In Hedera, every synthetic child transaction produced by a contract call shares the parent's `(payerAccountId, validStartNs)` with an incrementing nonce. A contract that spawns N child calls produces N+1 rows all matching the same key. There is no upper bound on N enforced at the query level.

**Exploit flow:**
1. Attacker identifies (from public chain data) a parent transaction whose contract execution produced a large number of child/synthetic transactions (e.g., a batch token-transfer contract with 500–1000 child calls). All children share the same `payerAccountId` and `validStartNs`.
2. Attacker enables the opcode endpoint (it is disabled by default but the question scope assumes it is enabled) and sends `GET /api/v1/contracts/results/{payerAccountId}-{validStartSec}-{validStartNano}/opcodes` with `Accept-Encoding: gzip`.
3. Each request causes the DB to scan and return all N+1 matching rows. Only row 0 is used; the rest are wasted.
4. The global opcode rate-limit bucket (`opcodeRateLimitBucket`) is a single in-memory `Bucket` shared across all callers — it is **not per-IP and not distributed**. In a multi-replica deployment each pod has its own bucket, so the effective global rate is `replicas × 1 RPS`. The attacker can saturate every replica's slot.

**Why existing checks are insufficient:**

- **`throttleOpcodeRequest()` (1 RPS global):** Limits request frequency but does not bound the number of rows fetched per request. The attacker's single allowed request per second still triggers a full table scan returning thousands of rows. Furthermore, the bucket is in-memory and not shared across replicas, so horizontal scaling multiplies the effective attack rate.
- **`statementTimeout = 3000 ms`:** Limits wall-clock query time, not row count. A query returning 1000 rows easily completes within 3 seconds.
- **`requestTimeout = 10000 ms`:** Application-level timeout; does not prevent the DB work from completing.

### Impact Explanation

Each attacker request causes the DB to read, serialize, and transmit an unbounded number of `Transaction` rows over the JDBC connection, consuming DB CPU, memory, and network bandwidth proportional to the child-transaction count. At 1 RPS (or N RPS across replicas), this produces a sustained amplified DB load. Legitimate users are simultaneously denied access to the opcode endpoint because the global token bucket is consumed by the attacker's heavy requests. This constitutes a griefing/DoS against the opcode debugging feature with no economic cost to the attacker.

### Likelihood Explanation

The endpoint must be explicitly enabled (`hiero.mirror.web3.opcode.tracer.enabled = true`), which reduces the default attack surface. However, when enabled (e.g., on a debug/testnet deployment), the preconditions are trivially met: parent transactions with many children are publicly visible on-chain, the transaction ID format is well-documented, and no authentication is required. The attack requires only an HTTP client and knowledge of one high-child-count transaction ID.

### Recommendation

1. **Add `LIMIT 1` to the repository query** — since only `getFirst()` is ever used, rewrite the method to return `Optional<Transaction>` using a derived query with `Top1`:
   ```java
   Optional<Transaction> findFirstByPayerAccountIdAndValidStartNsOrderByConsensusTimestampAsc(
           EntityId payerAccountId, long validStartNs);
   ```
   This eliminates the unbounded fetch entirely.

2. **Make the rate-limit bucket per-IP** using a `ConcurrentHashMap<String, Bucket>` keyed on the client IP, or use a distributed rate-limiter (e.g., bucket4j with Redis) so the limit is enforced globally across replicas.

### Proof of Concept

```
# Precondition: opcode endpoint enabled; identify a transaction with many children
# e.g., payerAccountId=0.0.12345, validStart=1700000000.123456789 with 800 child txns

# Step 1 – confirm child count via mirror REST API
curl "https://<mirror>/api/v1/transactions/0.0.12345-1700000000-123456789"
# Observe nonce values 0..800 all sharing the same transaction_id

# Step 2 – repeatedly call opcode endpoint (each call fetches all 801 rows, uses only row 0)
while true; do
  curl -s -H "Accept-Encoding: gzip" \
    "https://<web3>/api/v1/contracts/results/0.0.12345-1700000000-123456789/opcodes" \
    -o /dev/null
  sleep 1   # stay within 1 RPS global throttle
done

# Result: DB executes unbounded SELECT returning 801 Transaction rows per second,
# consuming DB I/O proportional to child count, while blocking all other users
# from the opcode endpoint (global token exhausted).
```