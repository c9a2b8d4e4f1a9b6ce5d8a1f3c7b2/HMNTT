All code references have been verified against the actual repository. Here is the result:

---

Audit Report

## Title
Unbounded Non-Terminating gRPC Stream via Non-Existent Topic When `checkTopicExists` Is Disabled

## Summary
When `hiero.mirror.grpc.checkTopicExists` is set to `false`, any unauthenticated caller can invoke `subscribeTopic()` with an arbitrary non-existent `topicID` and no `endTime`, causing the server to open a Reactive stream that never emits and never self-terminates. Each such call holds a live server-side gRPC HTTP/2 stream and a Redis topic subscription open for up to 600 seconds (the nginx proxy read timeout). An attacker repeating this across many TCP connections can exhaust server resources and deny service to legitimate subscribers.

## Finding Description

**Root cause — `topicExists()` in `TopicMessageServiceImpl`:**

When the entity is not found and `checkTopicExists=false`, the method synthesizes a fake `TOPIC` entity instead of raising `EntityNotFoundException`, allowing the subscription pipeline to proceed as if the topic were valid. [1](#0-0) 

**Termination signal — `pastEndTime()`:**

When no `endTime` is provided, `pastEndTime()` unconditionally returns `Flux.never()`. The `takeUntilOther(Flux.never())` call therefore never fires. [2](#0-1) 

**`isComplete()` always returns `false` when `endTime == null`:** [3](#0-2) 

**The merged flux pipeline:**

`historical` completes quickly (no messages for a non-existent topic). The `safetyCheck` fires once after 1 second via `Schedulers.boundedElastic()`, queries the DB (returns empty), and completes. The `live` flux calls `topicListener.listen(newFilter)`, which for the default Redis listener subscribes to a Redis channel `topic.{id}` that will never receive messages for a non-existent topic — it stays open indefinitely. [4](#0-3) [5](#0-4) 

**Test suite explicitly confirms the non-terminating behavior:**

The `topicNotFoundWithCheckTopicExistsFalse` test uses `expectNoEvent(WAIT).thenCancel()` — the stream produces nothing and requires external cancellation to terminate. [6](#0-5) 

**Controller layer — no authentication:**

`ConsensusController.subscribeTopic()` has no authentication or per-client rate limiting. [7](#0-6) 

**Per-connection cap only — not a global cap:**

`maxConcurrentCallsPerConnection = 5` is a per-connection limit. An attacker opens many TCP connections, each carrying 5 zombie streams. [8](#0-7) [9](#0-8) 

**nginx proxy 600-second read timeout:**

Each zombie stream lives for up to 10 minutes before the proxy closes it, but the attacker can continuously replenish them. [10](#0-9) 

**Default value of `checkTopicExists` is `true`:** [11](#0-10) 

**Documented as a supported operator option:** [12](#0-11) 

## Impact Explanation

Each zombie subscription holds: one gRPC HTTP/2 stream, one Redis channel subscription (via `ReactiveRedisMessageListenerContainer`), and one entry in the `subscriberCount` gauge. With enough connections (each carrying 5 streams), the attacker can exhaust file descriptors and starve legitimate subscribers. The `GrpcHighFileDescriptors` and `GrpcHighDBConnections` alerts confirm operators are aware these are real resource ceilings. [13](#0-12) [14](#0-13) 

## Likelihood Explanation

Precondition: operator has set `checkTopicExists=false` (a documented, supported, non-default configuration). The attacker needs no credentials, no special knowledge beyond the public gRPC proto schema, and no privileged network position. The attack is trivially scriptable: open TCP connections in a loop, send `subscribeTopic` with a random non-existent `topicID` and no `endTime`, never close the stream. The 600-second proxy timeout means each wave of connections occupies resources for 10 minutes, requiring only ~6 requests/minute per connection to maintain saturation.

## Recommendation

1. **Add a global concurrent subscription cap** in `GrpcConfiguration` using `NettyServerBuilder.maxConnectionAge()` or a server-wide semaphore, independent of per-connection limits.
2. **Add a server-side idle stream timeout** for subscriptions that have emitted zero messages after a configurable grace period (e.g., 30 seconds), terminating them with `DEADLINE_EXCEEDED`.
3. **Document the DoS risk** of `checkTopicExists=false` explicitly in `docs/configuration.md` alongside the property definition.
4. **Consider removing `checkTopicExists=false`** as a supported option, or restricting it to authenticated callers only.

## Proof of Concept

```bash
# Requires grpcurl and a deployment with checkTopicExists=false
for i in $(seq 1 100); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 999999999}}' \
    <host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
# Each call opens a stream that never emits and never terminates.
# With maxConcurrentCallsPerConnection=5, open 20+ TCP connections
# to bypass the per-connection limit.
# Monitor: hiero_mirror_grpc_subscribers gauge will climb unboundedly.
```

Each stream holds a Redis subscription to channel `topic.999999999` (which never receives messages) and a gRPC HTTP/2 stream open for up to 600 seconds per the nginx `grpc_read_timeout`. [15](#0-14) [16](#0-15)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-73)
```java
        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L64-66)
```java
    private Topic getTopic(TopicMessageFilter filter) {
        return ChannelTopic.of(String.format("topic.%d", filter.getTopicId().getId()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L68-79)
```java
    private Flux<TopicMessage> subscribe(Topic topic) {
        Duration interval = listenerProperties.getInterval();

        return container
                .flatMapMany(r -> r.receive(Collections.singletonList(topic), channelSerializer, messageSerializer))
                .map(Message::getMessage)
                .doOnCancel(() -> unsubscribe(topic))
                .doOnComplete(() -> unsubscribe(topic))
                .doOnError(t -> log.error("Error listening for messages", t))
                .doOnSubscribe(s -> log.info("Creating shared subscription to {}", topic))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/service/TopicMessageServiceTest.java (L132-143)
```java
    void topicNotFoundWithCheckTopicExistsFalse() {
        grpcProperties.setCheckTopicExists(false);
        var filter = TopicMessageFilter.builder().topicId(EntityId.of(999L)).build();

        StepVerifier.withVirtualTime(() -> topicMessageService.subscribeTopic(filter))
                .expectSubscription()
                .expectNoEvent(WAIT)
                .thenCancel()
                .verify(WAIT);

        grpcProperties.setCheckTopicExists(true);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L42-53)
```java
    @Override
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** docker-compose.yml (L225-226)
```yaml
        # Setting 600s read timeout for topic subscription. When the client receives a message the timeout resets to 0.
        location = /com.hedera.mirror.api.proto.ConsensusService/subscribeTopic { grpc_read_timeout 600s; grpc_pass grpc://grpc_host; }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** docs/configuration.md (L409-409)
```markdown
| `hiero.mirror.grpc.checkTopicExists`                       | true             | Whether to throw an error when the topic doesn't exist                                                    |
```

**File:** charts/hedera-mirror-grpc/values.yaml (L209-231)
```yaml
  GrpcHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror gRPC API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="grpc"}) by (namespace, pod) / sum(hikaricp_connections_max{application="grpc"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource

  GrpcHighFileDescriptors:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} file descriptor usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror gRPC API file descriptor usage exceeds 80%"
    enabled: true
    expr: sum(process_files_open_files{application="grpc"}) by (namespace, pod) / sum(process_files_max_files{application="grpc"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      severity: critical
      application: grpc
      area: resource
```

**File:** charts/hedera-mirror-common/alerts/rules.tf (L67-126)
```terraform
  rule {
    name      = "GrpcHighDBConnections"
    condition = "A"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "grafanacloud-prom"
      model          = "{\"editorMode\":\"code\",\"expr\":\"sum by (cluster, namespace, pod) (hikaricp_connections_active{application=\\\"grpc\\\"}) / sum by (cluster, namespace, pod) (hikaricp_connections_max{application=\\\"grpc\\\"}) > 0.75\",\"instant\":true,\"intervalMs\":1000,\"legendFormat\":\"__auto\",\"maxDataPoints\":43200,\"range\":false,\"refId\":\"A\"}"
    }

    no_data_state  = "NoData"
    exec_err_state = "Error"
    for            = "5m"
    annotations = {
      description = "{{ $labels.cluster }}: {{ $labels.namespace }}/{{ $labels.pod }} is using {{ (index $values \"A\").Value | humanizePercentage }} of available database connections"
      summary     = "[{{ $labels.cluster }}] Mirror gRPC API database connection utilization exceeds 75%"
    }
    labels = {
      application = "grpc"
      area        = "resource"
      severity    = "critical"
    }
    is_paused = false
  }
  rule {
    name      = "GrpcHighFileDescriptors"
    condition = "A"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "grafanacloud-prom"
      model          = "{\"editorMode\":\"code\",\"expr\":\"sum by (cluster, namespace, pod) (process_files_open_files{application=\\\"grpc\\\"}) / sum by (cluster, namespace, pod) (process_files_max_files{application=\\\"grpc\\\"}) > 0.8\",\"instant\":true,\"intervalMs\":1000,\"legendFormat\":\"__auto\",\"maxDataPoints\":43200,\"range\":false,\"refId\":\"A\"}"
    }

    no_data_state  = "NoData"
    exec_err_state = "Error"
    for            = "5m"
    annotations = {
      description = "{{ $labels.cluster }}: {{ $labels.namespace }}/{{ $labels.pod }} file descriptor usage reached {{ (index $values \"A\").Value | humanizePercentage }}"
      summary     = "[{{ $labels.cluster }}] Mirror gRPC API file descriptor usage exceeds 80%"
    }
    labels = {
      application = "grpc"
      area        = "resource"
      severity    = "critical"
    }
    is_paused = false
  }
```
