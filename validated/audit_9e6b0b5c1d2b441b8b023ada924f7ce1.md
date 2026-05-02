All referenced code has been verified. Here is my assessment:

**Verified facts:**
- `GrpcClientSDK.toResponse()` at line 72 calls `Utility.getTimestamp(topicMessage.contents)` and uses the result directly as `publishedTimestamp` with no origin check. [1](#0-0) 
- `Utility.getTimestamp()` parses the first space-delimited token of raw bytes as a millisecond-epoch timestamp, with the only guard being a ±5-minute window (`MILLIS_OFFSET`). [2](#0-1) 
- `subscribeToClient()` subscribes to ALL messages on the topic without any origin or content filtering. [3](#0-2) 
- `SubscribeMetrics.onNext()` directly uses `publishedTimestamp` to compute and record the `hiero.mirror.monitor.subscribe.e2e` latency timer, which feeds production alerts. [4](#0-3) 
- The `MonitorSubscribeLatency` alert fires when `hiero_mirror_monitor_subscribe_e2e_seconds` exceeds 14 s, directly driven by this metric. [5](#0-4) 

---

Audit Report

## Title
Unprivileged Metric Manipulation via Crafted HCS Topic Message Timestamp

## Summary
`GrpcClientSDK.toResponse()` blindly trusts the `publishedTimestamp` parsed from the raw byte contents of any message received on the monitored HCS topic. Because any network participant can submit messages to an unprotected topic (one without a `submitKey`), an attacker can craft a message whose contents encode a timestamp within the ±5-minute acceptance window, causing the monitor to record a false end-to-end latency and skew its observability metrics.

## Finding Description
**`GrpcClientSDK.toResponse()`** extracts the published timestamp directly from message contents with no origin check:

```java
Instant publishedTimestamp = Utility.getTimestamp(topicMessage.contents);
``` [6](#0-5) 

**`Utility.getTimestamp()`** parses the first space-delimited token of the raw bytes as a millisecond-epoch timestamp. The only validation is a ±5-minute window:

```java
private static final long MILLIS_OFFSET = Duration.ofMinutes(5L).toMillis();
// ...
if (timestamp == null || timestamp < (now - MILLIS_OFFSET) || timestamp > (now + MILLIS_OFFSET)) {
    return null;
}
``` [7](#0-6) 

**`subscribeToClient()`** subscribes to ALL messages on the topic without any filtering by sender, sequence number, or content signature: [3](#0-2) 

**Exploit flow:**
1. Attacker identifies the HCS topic ID the monitor subscribes to (visible in logs or config).
2. Attacker submits a message to that topic (requires only HBAR fees; no `submitKey` needed on unprotected topics) with contents like `<epoch_ms_within_5min_window> <padding>`.
3. The monitor receives the message; `Utility.getTimestamp()` accepts the crafted timestamp (it passes the ±5-minute guard); `toResponse()` builds a `SubscribeResponse` with `publishedTimestamp` set to the attacker-controlled value.
4. `SubscribeMetrics.onNext()` computes `Duration.between(publishedTimestamp, receivedTimestamp)` and records it into the `hiero.mirror.monitor.subscribe.e2e` timer.

**Why the existing check is insufficient:** The ±5-minute guard still leaves a 10-minute exploitable window. Setting the timestamp to `now − 299 s` causes the monitor to record ~5-minute latency; setting it to `now + 299 s` produces near-zero or negative latency. Neither case is rejected. [8](#0-7) 

## Impact Explanation
The `hiero.mirror.monitor.subscribe.e2e` metric is the direct input to the `MonitorSubscribeLatency` production alert (threshold: 14 s). Injecting false values can:
- **Inflate** reported latency, triggering false high-latency alerts and causing operators to believe the network or mirror node is degraded when it is not.
- **Deflate** reported latency, masking genuine performance regressions.
- **Undermine** the integrity of the monitoring system that operators rely on to make operational decisions. [4](#0-3) 

## Likelihood Explanation
- **Precondition:** The monitored topic must lack a `submitKey`. This is common for monitoring/test topics where ease of use is prioritized.
- **Cost:** Submitting an HCS message costs a small HBAR fee (~$0.0001), making repeated attacks trivially cheap.
- **Knowledge required:** The topic ID is often logged or exposed in configuration; no privileged access is needed.
- **Repeatability:** The attacker can submit messages continuously to maintain persistent metric corruption.

## Recommendation
1. **Correlate by sequence number:** The monitor's publisher should record the sequence numbers of messages it submits. `GrpcSubscription.onNext()` already logs sequence numbers; extend this to reject messages whose sequence numbers were not issued by the local publisher.
2. **Embed a shared secret or HMAC:** The publisher (`Utility.generateMessage()`) should embed an HMAC or a shared secret token in the message body. `Utility.getTimestamp()` should verify this token before accepting the timestamp.
3. **Use a topic with a `submitKey`:** Configure the monitored HCS topic with a `submitKey` controlled by the monitor operator, so only the monitor's publisher can submit messages.
4. **Tighten the time window:** Reduce `MILLIS_OFFSET` to a value consistent with expected network latency (e.g., 30 seconds) to shrink the exploitable window.

## Proof of Concept
```
# Craft a message with a timestamp 4 minutes in the past (within the ±5-min window)
TOPIC_ID="0.0.XXXXX"
TIMESTAMP_MS=$(( $(date +%s%3N) - 240000 ))
MESSAGE="${TIMESTAMP_MS} padding"

# Submit via Hedera SDK or hedera-cli (no submitKey required on unprotected topic)
hedera topic submit --topic-id $TOPIC_ID --message "$MESSAGE"

# The monitor will receive this message, accept the crafted timestamp,
# and record ~240-second (4-minute) latency into hiero_mirror_monitor_subscribe_e2e,
# potentially triggering the MonitorSubscribeLatency alert (threshold: 14s).
```

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/grpc/GrpcClientSDK.java (L52-68)
```java
    private Flux<SubscribeResponse> subscribeToClient(Client client, GrpcSubscription subscription) {
        Sinks.Many<TopicMessage> sink = Sinks.many().multicast().directBestEffort();

        TopicMessageQuery topicMessageQuery = subscription.getTopicMessageQuery();
        topicMessageQuery.setCompletionHandler(sink::tryEmitComplete);
        topicMessageQuery.setErrorHandler((throwable, topicMessage) -> sink.tryEmitError(throwable));
        topicMessageQuery.setMaxAttempts(0); // Disable since we use our own retry logic to capture errors
        SubscriptionHandle subscriptionHandle = topicMessageQuery.subscribe(client, sink::tryEmitNext);

        return sink.asFlux()
                .publishOn(Schedulers.parallel())
                .doFinally(s -> subscriptionHandle.unsubscribe())
                .doOnComplete(subscription::onComplete)
                .doOnError(subscription::onError)
                .doOnNext(subscription::onNext)
                .map(t -> toResponse(subscription, t));
    }
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

**File:** monitor/src/main/java/org/hiero/mirror/monitor/util/Utility.java (L18-52)
```java
    private static final long MILLIS_OFFSET = Duration.ofMinutes(5L).toMillis();

    /**
     * Parses bytes as a String expected to be in format ^\d+ .*$. The first part is the published timestamp in
     * milliseconds from epoch followed by a mandatory space. Optionally, additional arbitrary characters can be
     * appended that are ignored by this method.
     *
     * @param bytes containing a timestamp encoded as a String
     * @return the parsed Instant
     */
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

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/SubscribeMetrics.java (L36-46)
```java
    public void onNext(SubscribeResponse response) {
        log.trace("Response: {}", response);
        Scenario<?, ?> scenario = response.getScenario();
        Instant publishedTimestamp = response.getPublishedTimestamp();
        durationMetrics.computeIfAbsent(scenario, this::newDurationGauge);

        if (publishedTimestamp != null) {
            Duration latency = Duration.between(publishedTimestamp, response.getReceivedTimestamp());
            latencyMetrics.computeIfAbsent(scenario, this::newLatencyTimer).record(latency);
        }
    }
```

**File:** charts/hedera-mirror-common/alerts/rules.tf (L1133-1160)
```terraform
  rule {
    name      = "MonitorSubscribeLatency"
    condition = "A"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "grafanacloud-prom"
      model          = "{\"editorMode\":\"code\",\"expr\":\"sum(rate(hiero_mirror_monitor_subscribe_e2e_seconds_sum{application=\\\"monitor\\\"}[2m])) by (cluster, namespace, pod, scenario, subscriber) / sum(rate(hiero_mirror_monitor_subscribe_e2e_seconds_count{application=\\\"monitor\\\"}[2m])) by (cluster, namespace, pod, scenario, subscriber) > 14\",\"instant\":true,\"intervalMs\":1000,\"legendFormat\":\"__auto\",\"maxDataPoints\":43200,\"range\":false,\"refId\":\"A\"}"
    }

    no_data_state  = "NoData"
    exec_err_state = "Error"
    for            = "5m"
    annotations = {
      description = "{{ $labels.cluster }}: Latency averaging {{ (index $values \"A\").Value | humanizeDuration }} for '{{ $labels.scenario }}' #{{ $labels.subscriber }} scenario for {{ $labels.namespace }}/{{ $labels.pod }}"
      summary     = "[{{ $labels.cluster }}] End to end latency exceeds 14s"
    }
    labels = {
      application = "monitor"
      severity    = "critical"
    }
    is_paused = false
```
