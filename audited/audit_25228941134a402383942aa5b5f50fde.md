### Title
Unauthenticated Binary Oracle in `getMessageByConsensusTimestamp` Leaks Transaction Type and Result

### Summary
The public endpoint `GET /api/v1/topics/messages/:consensusTimestamp` acts as a binary oracle: a 200 response confirms that the supplied nanosecond timestamp corresponds to a `CONSENSUSSUBMITMESSAGE` transaction (type=27) with result `SUCCESS` (result=22), while a 404 confirms it does not. No topic ID, authentication, or any other credential is required. An attacker who already knows (or can enumerate) a consensus timestamp can therefore confirm the transaction type and outcome without possessing any privileged information.

### Finding Description
**Exact code path:**

`rest/server.js` line 129 registers the route with no authentication middleware: [1](#0-0) 

`rest/topicmessage.js` `getMessageByConsensusTimestamp` (lines 60–81) performs only format validation on the timestamp, then immediately executes:

```sql
select consensus_timestamp, entity_id
from transaction
where consensus_timestamp = $1 and result = 22 and type = 27
``` [2](#0-1) 

If `rows.length !== 1` the function throws `NotFoundError` (HTTP 404); otherwise it returns HTTP 200 with the full topic message payload. [3](#0-2) 

**Root cause / failed assumption:** The design assumes that knowing a nanosecond-precision consensus timestamp is already sufficient proof of authorization to receive the message. In reality, the 200/404 response itself encodes the boolean predicate `(type=27 AND result=22)` for any timestamp the caller supplies — leaking transaction metadata before any topic-level access check is performed.

**Why existing checks are insufficient:**
- `validateConsensusTimestampParam` only validates the timestamp format (seconds[.nanoseconds]). [4](#0-3) 
- `utils.validateReq(req)` performs generic request sanitation, not authorization.
- There is no rate-limiting, authentication, or topic-membership check before the transaction-table query.

### Impact Explanation
An attacker learns, for any nanosecond timestamp they supply:
1. Whether a transaction was finalized at that exact instant.
2. Whether it was a `CONSENSUSSUBMITMESSAGE` (type 27).
3. Whether it succeeded (result 22).

This is a direct information-disclosure of transaction type and result without knowing the topic ID. In HCS deployments where topic IDs are kept private (e.g., enterprise or permissioned topics), this oracle breaks the confidentiality model: an adversary can confirm that a private topic received a successful message at a known time, enabling correlation attacks and traffic-analysis of private topic activity.

### Likelihood Explanation
Consensus timestamps are nanosecond-precision Unix epoch values. They are already exposed by other public mirror-node endpoints (e.g., `GET /api/v1/transactions`). An attacker can:
- Harvest timestamps from the public transactions API.
- Feed each one to this endpoint.
- Classify every timestamp as "successful CONSENSUSSUBMITMESSAGE" or "not."

No special tooling, credentials, or network position is required. The attack is fully automated, repeatable, and produces no server-side audit trail distinguishable from normal API usage.

### Recommendation
1. **Decouple the oracle from the response code.** Do not return a distinct 404 vs 200 based solely on `type=27 AND result=22`. If the timestamp exists but belongs to a different transaction type, return the same 404 as when it does not exist at all — do not allow the response to encode the predicate.
2. **Move the type/result filter after the topic-message join.** Query `topic_message` first (using the timestamp alone), then validate the corresponding transaction row. This way the 404 path is indistinguishable regardless of transaction type or result.
3. **Consider access control on private topics.** If topics can be private, the endpoint should verify the caller is authorized to read from the resolved topic before returning any response.

### Proof of Concept
```
# Step 1 – obtain any consensus timestamp from the public transactions API
GET /api/v1/transactions?limit=1
# → note consensus_timestamp, e.g. "1234567890.000000001"

# Step 2 – probe the topic-message oracle
GET /api/v1/topics/messages/1234567890.000000001

# Interpretation:
#   HTTP 200  → timestamp is a CONSENSUSSUBMITMESSAGE (type=27) with result SUCCESS (result=22)
#   HTTP 404  → timestamp is NOT a successful CONSENSUSSUBMITMESSAGE

# Step 3 – automate over a range of timestamps to map all successful HCS submissions
for ts in $(seq 1234567890000000000 1 1234567890000001000); do
  formatted=$(python3 -c "t=$ts; print(f'{t//1000000000}.{t%1000000000:09d}')")
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://mirror.example.com/api/v1/topics/messages/$formatted")
  [ "$status" = "200" ] && echo "HCS SUCCESS at $formatted"
done
```

### Citations

**File:** rest/server.js (L129-129)
```javascript
app.getExt(`${apiPrefix}/topics/messages/:consensusTimestamp`, topicmessage.getMessageByConsensusTimestamp);
```

**File:** rest/topicmessage.js (L22-26)
```javascript
const validateConsensusTimestampParam = (consensusTimestamp) => {
  if (!utils.isValidTimestampParam(consensusTimestamp)) {
    throw InvalidArgumentError.forParams(TopicMessage.CONSENSUS_TIMESTAMP);
  }
};
```

**File:** rest/topicmessage.js (L60-73)
```javascript
const getMessageByConsensusTimestamp = async (req, res) => {
  utils.validateReq(req);
  const consensusTimestampParam = req.params.consensusTimestamp;
  validateConsensusTimestampParam(consensusTimestampParam);

  const consensusTimestamp = utils.parseTimestampParam(consensusTimestampParam);

  let query = `select consensus_timestamp, entity_id
    from transaction
    where consensus_timestamp = $1 and result = 22 and type = 27`;
  const {rows} = await pool.queryQuietly(query, consensusTimestamp);
  if (rows.length !== 1) {
    throw new NotFoundError();
  }
```
