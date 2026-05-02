### Title
Unfiltered `Retry.backoff(Long.MAX_VALUE, ...)` in `subscribe()` Enables Infinite Retry Loop on Non-Transient Deserialization Errors

### Summary
The `subscribe()` method in `RedisTopicListener` applies `Retry.backoff(Long.MAX_VALUE, interval)` with no error-type filter, meaning it retries on every `Throwable` including non-transient `SerializationException` thrown by `Jackson2JsonRedisSerializer` when msgpack deserialization fails. An attacker with access to the Redis pub/sub layer (unauthenticated by default) can publish a single malformed msgpack frame to a predictable `topic.{id}` channel, causing the shared Flux to error, retry, re-subscribe, error again, and loop indefinitely — permanently denying message delivery to all gRPC subscribers of that topic.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java`, `subscribe()`, lines 68–79:

```java
return container
    .flatMapMany(r -> r.receive(
        Collections.singletonList(topic), channelSerializer, messageSerializer))  // line 72
    .map(Message::getMessage)
    ...
    .retryWhen(Retry.backoff(Long.MAX_VALUE, interval)          // line 78
               .maxBackoff(interval.multipliedBy(4L)));         // no .filter() call
```

**Serializer:**

`grpc/src/main/java/org/hiero/mirror/grpc/config/RedisConfiguration.java`, lines 34–41:
```java
var objectMapper = new ObjectMapper(new MessagePackFactory());
return new Jackson2JsonRedisSerializer<>(objectMapper, TopicMessage.class);
```

`Jackson2JsonRedisSerializer.deserialize()` wraps any `JsonProcessingException` in a `SerializationException` and throws it synchronously inside the `receive()` Flux. In Project Reactor, a synchronous exception thrown inside a `flatMapMany` operator propagates as an `onError` signal that terminates the stream.

**Root cause / failed assumption:**

The design assumes that any error reaching `retryWhen` is a transient infrastructure error (e.g., Redis connection drop). This assumption fails because the deserialization step sits *inside* the same Flux chain, upstream of `retryWhen`. A `SerializationException` caused by a permanently malformed payload is non-transient: retrying re-subscribes to the same channel and will immediately receive the same (or next) malformed message, producing the same error, forever.

**Why existing checks are insufficient:**

- `doOnError` (line 76) only logs; it does not filter or transform the error.
- `Retry.backoff` has a `.filter(Predicate<Throwable>)` API that is never called here.
- `doOnCancel` / `doOnComplete` (lines 74–75) are not invoked during a `retryWhen` cycle, so the topic is never removed from `topicMessages`, and all new gRPC subscribers receive the same broken, looping Flux via `.share()`.

### Impact Explanation

Every gRPC client subscribed to the targeted topic ID receives no messages for the duration of the attack. The shared Flux (`topicMessages` map entry) is permanently stuck in a retry loop — new subscribers joining via `computeIfAbsent` get the same broken Flux. Each retry iteration opens a new Redis subscription before the previous one is torn down, causing connection-handle leakage. With `Long.MAX_VALUE` retries and a max backoff of only `4 × interval` (default: 2 seconds), the loop fires continuously, consuming CPU and Redis connections. Recovery requires a service restart.

### Likelihood Explanation

Redis pub/sub has no built-in access control; the default Redis configuration requires no authentication (`requirepass` is unset). Channel names follow the trivially guessable pattern `topic.<numeric_id>`. Any attacker with TCP reachability to the Redis port — a low bar in many Kubernetes or internal-network deployments — can publish a single malformed msgpack frame using the standard Redis `PUBLISH` command. No gRPC credentials, no application account, and no prior knowledge beyond the topic ID are required. The attack is repeatable and scriptable.

### Recommendation

1. **Filter the retry predicate** to only retry on transient infrastructure errors:
   ```java
   .retryWhen(Retry.backoff(Long.MAX_VALUE, interval)
       .maxBackoff(interval.multipliedBy(4L))
       .filter(t -> !(t instanceof SerializationException)
                 && !(t instanceof InvalidDefinitionException)))
   ```
2. **Cap the retry count** to a finite value and surface a terminal error after exhaustion so the `topicMessages` entry is evicted and the topic can be re-subscribed cleanly.
3. **Handle deserialization errors per-message** (e.g., via `.onErrorContinue()` scoped to the inner `flatMapMany`) so a single bad frame does not terminate the entire subscription stream.
4. **Enable Redis AUTH** (`requirepass`) and restrict `PUBLISH` permissions to the importer service account only.

### Proof of Concept

**Preconditions:** Redis reachable on default port 6379, no `requirepass` set (default), target topic ID known (e.g., `1001`).

```bash
# 1. Connect to Redis with redis-cli (no credentials needed)
redis-cli -h <redis-host> -p 6379

# 2. Publish a single malformed msgpack payload to the target topic channel.
#    The byte sequence below is not valid msgpack and will cause
#    Jackson2JsonRedisSerializer to throw SerializationException.
PUBLISH topic.1001 "\xff\xfe\x00\x00GARBAGE"

# 3. Observe in grpc-service logs:
#    ERROR Error listening for messages
#    INFO  Creating shared subscription to topic.1001   <- retry fires
#    ERROR Error listening for messages                 <- immediate re-failure
#    INFO  Creating shared subscription to topic.1001   <- retry fires again
#    ... repeating indefinitely

# 4. Any gRPC client subscribed to topic 1001 receives zero messages
#    until the grpc service is restarted.
```