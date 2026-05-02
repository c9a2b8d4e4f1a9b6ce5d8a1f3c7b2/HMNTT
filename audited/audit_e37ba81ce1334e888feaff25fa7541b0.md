### Title
Unprivileged Metric Manipulation via Crafted HCS Topic Message Timestamp

### Summary
The `GrpcClientSDK.toResponse()` method blindly trusts the `publishedTimestamp` parsed from the raw byte contents of any message received on the monitored HCS topic. Because any network participant can submit messages to an unprotected topic (one without a `submitKey`), an attacker can craft a message whose contents encode a timestamp within the ±5-minute acceptance window, causing the monitor to record a false end-to-end latency for that message and skew its observability metrics.

### Finding Description
**Code path:**

`GrpcClientSDK.toResponse()` — [1](#0-0) 

```
Instant publishedTimestamp = Utility.getTimestamp(topicMessage.contents);
```

`Utility.getTimestamp()` parses the first space-delimited token of the raw message bytes as a millisecond-epoch timestamp: [2](#0-1) 

The only validation is a ±5-minute window check: [3](#0-2) 

**Root cause / failed assumption:** The monitor assumes that only its own publisher places messages on the topic, so it treats the embedded timestamp as authoritative. There is no cryptographic signature, sequence-number correlation, or origin check. The `subscribeToClient()` method subscribes to ALL messages on the topic without filtering: [4](#0-3) 

**Exploit flow:**
1. Attacker identifies the HCS topic ID the monitor is subscribed to (visible in logs or config).
2. Attacker submits a message to that topic (requires only HBAR for fees; no `submitKey` needed if the topic is unprotected) with contents like `<epoch_ms_within_5min_window> <padding>`.
3. The monitor receives the message, `Utility.getTimestamp()` accepts the crafted timestamp (it passes the ±5-minute guard), and `toResponse()` builds a `SubscribeResponse` with `publishedTimestamp` set to the attacker-controlled value.
4. The resulting `SubscribeResponse` is emitted into the monitoring pipeline with a false latency.

**Why the existing check is insufficient:** The ±5-minute guard (`MILLIS_OFFSET = Duration.ofMinutes(5L).toMillis()`) still leaves a 10-minute exploitable window. An attacker setting the timestamp to `now − 299 seconds` causes the monitor to record ~5-minute latency for that message. Setting it to `now + 299 seconds` produces a negative or near-zero latency reading. Neither case is rejected. [5](#0-4) 

### Impact Explanation
The monitor's latency statistics (end-to-end publish-to-receive duration) are derived from `publishedTimestamp`. Injecting false values can:
- Inflate reported latency, triggering false high-latency alerts and causing operators to believe the network or mirror node is degraded when it is not.
- Deflate reported latency, masking genuine performance regressions.
- Undermine the integrity of the monitoring system that operators rely on to make operational decisions.

No funds are moved, but the transaction timeline as recorded by the monitor is falsified, matching the stated scope of "reorganizing transaction history without direct theft of funds."

### Likelihood Explanation
- **Precondition:** The monitored topic must lack a `submitKey`. This is common for monitoring/test topics where ease of use is prioritized.
- **Cost:** Submitting an HCS message costs a small HBAR fee (~$0.0001), making repeated attacks trivially cheap.
- **Knowledge required:** The topic ID is often logged or exposed in configuration; no privileged access is needed.
- **Repeatability:** The attacker can submit messages continuously to maintain persistent metric corruption.

### Recommendation
1. **Authenticate message origin:** Embed a keyed HMAC (using a secret shared between the publisher and subscriber) in the message contents. `toResponse()` should verify the HMAC before trusting the timestamp.
2. **Require a `submitKey` on monitored topics:** Configure HCS topics with a `submitKey` so only the monitor's publisher can submit messages.
3. **Correlate by known publish IDs:** Have the publisher embed a unique, unpredictable nonce alongside the timestamp; the subscriber should only accept timestamps from messages whose nonce it recognizes.
4. **Treat `publishedTimestamp` as advisory only:** If the timestamp cannot be authenticated, exclude the message from latency calculations rather than recording a potentially attacker-controlled value.

### Proof of Concept
```
# 1. Identify the monitored topic ID from monitor logs or config.
# 2. Craft a message with a timestamp 4 minutes in the past (within the ±5 min window):
CRAFTED_TS=$(( $(date +%s%3N) - 240000 ))   # 240,000 ms = 4 minutes ago
MESSAGE="${CRAFTED_TS} attacker_padding"

# 3. Submit via Hedera SDK or hedera-cli (no submitKey required on unprotected topic):
hedera topic submit --topic-id 0.0.<TOPIC_ID> --message "${MESSAGE}"

# 4. Observe monitor logs/metrics: the monitor records a ~4-minute latency
#    for this message, skewing its end-to-end latency statistics.
``` [1](#0-0) [2](#0-1)

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/grpc/GrpcClientSDK.java (L59-67)
```java
        SubscriptionHandle subscriptionHandle = topicMessageQuery.subscribe(client, sink::tryEmitNext);

        return sink.asFlux()
                .publishOn(Schedulers.parallel())
                .doFinally(s -> subscriptionHandle.unsubscribe())
                .doOnComplete(subscription::onComplete)
                .doOnError(subscription::onError)
                .doOnNext(subscription::onNext)
                .map(t -> toResponse(subscription, t));
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/grpc/GrpcClientSDK.java (L70-87)
```java
    private SubscribeResponse toResponse(GrpcSubscription subscription, TopicMessage topicMessage) {
        Instant receivedTimestamp = Instant.now();
        Instant publishedTimestamp = Utility.getTimestamp(topicMessage.contents);

        if (publishedTimestamp == null) {
            log.warn(
                    "{} Invalid published timestamp for message with consensus timestamp {}",
                    subscription,
                    topicMessage.consensusTimestamp);
        }

        return SubscribeResponse.builder()
                .consensusTimestamp(topicMessage.consensusTimestamp)
                .publishedTimestamp(publishedTimestamp)
                .receivedTimestamp(receivedTimestamp)
                .scenario(subscription)
                .build();
    }
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/util/Utility.java (L18-18)
```java
    private static final long MILLIS_OFFSET = Duration.ofMinutes(5L).toMillis();
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/util/Utility.java (L28-52)
```java
    public static Instant getTimestamp(byte[] bytes) {
        try {
            if (bytes == null) {
                return null;
            }

            String message = new String(bytes, StandardCharsets.US_ASCII);
            String[] parts = StringUtils.split(message, ' ');
            if (parts == null || parts.length <= 1) {
                return null;
            }

            long now = System.currentTimeMillis();
            Long timestamp = Long.parseLong(parts[0]);

            // Discard unreasonable values
            if (timestamp == null || timestamp < (now - MILLIS_OFFSET) || timestamp > (now + MILLIS_OFFSET)) {
                return null;
            }

            return Instant.ofEpochMilli(timestamp);
        } catch (Exception e) {
            return null;
        }
    }
```
