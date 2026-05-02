### Title
Unbounded Multi-Connection Resource Exhaustion via Missing gRPC Connection and Rate Limits

### Summary
`grpcServerConfigurer()` configures `maxConcurrentCallsPerConnection = 5` as the sole admission control, but this limit applies only per-connection. No global connection count limit, no per-IP rate limit, and no gRPC-layer throttle exist. An unprivileged attacker opening many parallel connections can saturate the shared `applicationTaskExecutor` queue and exhaust the HikariCP database connection pool, causing legitimate streaming subscriptions (`subscribeTopic`, `getNodes`) to time out or be dropped.

### Finding Description
**Exact code path:**

`grpcServerConfigurer()` at [1](#0-0)  configures two things on the Netty server:
1. Delegates all call execution to the shared Spring `applicationTaskExecutor`.
2. Calls `serverBuilder.maxConcurrentCallsPerConnection(5)` — the default from [2](#0-1) .

**Root cause — failed assumption:** The code assumes `maxConcurrentCallsPerConnection` is a global admission control. It is not. It is a *per-connection* limit enforced by Netty's HTTP/2 `MAX_CONCURRENT_STREAMS` setting. There is no configured limit on the total number of accepted connections (`maxConnectionsTotal` / `maxConnectionAge` are never set), no per-IP connection rate limit, and no gRPC `ServerInterceptor` performing throttling. The only interceptor present is a test-scope utility that only sets endpoint context: [3](#0-2) .

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (plaintext, no auth required per docs: [4](#0-3) ).
2. On each connection the attacker immediately sends 5 concurrent server-streaming RPCs (`subscribeTopic` or `getNodes`), staying within the per-connection limit.
3. Each RPC dispatches a Reactor pipeline that calls `topicMessageService::subscribeTopic` / `networkService::getNodes`, both of which issue database queries through HikariCP.
4. With *N* connections × 5 calls = 5*N* concurrent tasks submitted to `applicationTaskExecutor`. Spring Boot's default `ThreadPoolTaskExecutor` has an unbounded task queue; tasks are accepted without back-pressure.
5. HikariCP's default pool size (10 connections) is exhausted almost immediately; all subsequent DB calls block waiting for a connection.
6. The `applicationTaskExecutor` thread pool fills with blocked threads; legitimate subscriber tasks queue indefinitely and eventually time out.

**Why the existing check is insufficient:**
`maxConcurrentCallsPerConnection = 5` only prevents a single client from opening more than 5 streams on one TCP connection. It does nothing to limit the aggregate load from many connections. No rate-limiting equivalent to the `web3` module's Bucket4j throttle ( [5](#0-4) ) exists in the `grpc` module.

### Impact Explanation
A single attacker machine can open thousands of TCP connections (OS default allows ~65 k outbound ports). At 5 streams per connection, even 200 connections yield 1 000 concurrent gRPC calls, which is sufficient to exhaust the DB pool and stall the executor. All legitimate `subscribeTopic` streaming subscriptions sharing the same `applicationTaskExecutor` and DB pool are starved, causing them to time out or be dropped. This is a complete denial-of-service of the gRPC service with no collateral damage to the attacker.

### Likelihood Explanation
Preconditions are minimal: the gRPC port is publicly reachable, no authentication is required (plaintext `-plaintext` flag shown in official docs), and standard gRPC client libraries make opening many connections trivial. The attack is repeatable and requires no special knowledge beyond the public API. Infrastructure-level mitigations (e.g., Traefik circuit-breaker in the Helm chart) only trigger on error-rate thresholds, not on connection volume: [6](#0-5) .

### Recommendation
1. **Add a global connection limit** in `grpcServerConfigurer()`:
   ```java
   serverBuilder.maxConnectionAge(30, TimeUnit.SECONDS);
   serverBuilder.maxConnectionAgeGrace(5, TimeUnit.SECONDS);
   ```
   and expose a `maxConnections` property in `NettyProperties`.
2. **Add a gRPC `ServerInterceptor`** that implements per-IP token-bucket rate limiting (analogous to `ThrottleConfiguration` in `web3`) and register it as a `@GlobalServerInterceptor`.
3. **Use a bounded `ThreadPoolTaskExecutor`** dedicated to gRPC (separate from the shared `applicationTaskExecutor`) with a bounded queue and a `CallerRunsPolicy` or rejection handler that returns `RESOURCE_EXHAUSTED` to the client.
4. **Expose `maxConcurrentCallsPerConnection`** as a documented operator-tunable property (already done) but add a companion `maxConnections` property to `NettyProperties`.

### Proof of Concept
```bash
# Open 200 connections, each with 5 concurrent subscribeTopic streams (1000 total)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
      <host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait

# Observe: legitimate subscribers begin timing out; DB pool exhausted in logs;
# executor queue depth climbs without bound.
```
Expected result: HikariCP logs `Connection is not available, request timed out`; existing streaming clients receive `DEADLINE_EXCEEDED` or are silently dropped as the executor queue backs up.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** docs/grpc/README.md (L16-16)
```markdown
`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** charts/hedera-mirror-grpc/values.yaml (L156-161)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.10 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 3
      initialInterval: 250ms
```
