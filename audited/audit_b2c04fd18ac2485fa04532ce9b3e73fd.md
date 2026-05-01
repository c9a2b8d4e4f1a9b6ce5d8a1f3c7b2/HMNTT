### Title
Cache Stampede via Unsynchronized `@Cacheable` on `addressBookEntryCache` with 2-Second Expiry

### Summary
The `findByConsensusTimestampAndNodeId` method in `AddressBookEntryRepository` is annotated with `@Cacheable` without `sync=true`, meaning Spring's proxy does not serialize cache-miss loads. When the 2-second Caffeine `expireAfterWrite` window elapses, all concurrent `getNodes()` callers simultaneously observe a cache miss and each independently fires the underlying SQL query against the database. An unauthenticated attacker can open many gRPC connections (each allowed up to 5 concurrent calls) and time requests to the expiry boundary, causing a repeating database query flood every 2 seconds.

### Finding Description

**Code path:**

1. `NetworkController.getNodes()` — `grpc/src/main/java/org/hiero/mirror/grpc/controller/NetworkController.java:33-38` — accepts unauthenticated gRPC calls, no rate limiting.
2. `NetworkServiceImpl.getNodes()` — `grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java:55-77` — creates a new `AddressBookContext` per call and pages through the repository.
3. `NetworkServiceImpl.page()` — lines 79-108 — calls `addressBookEntryRepository.findByConsensusTimestampAndNodeId(addressBookTimestamp, nextNodeId, pageSize)` for each page.
4. `AddressBookEntryRepository.findByConsensusTimestampAndNodeId()` — `grpc/src/main/java/org/hiero/mirror/grpc/repository/AddressBookEntryRepository.java:16-36` — annotated `@Cacheable(cacheManager = ADDRESS_BOOK_ENTRY_CACHE, cacheNames = CACHE_NAME, unless = "@spelHelper.isNullOrEmpty(#result)")` with **no `sync=true`**.
5. `CacheConfiguration.addressBookEntryCache()` — `grpc/src/main/java/org/hiero/mirror/grpc/config/CacheConfiguration.java:25-34` — builds a Caffeine cache with `.expireAfterWrite(addressBookProperties.getCacheExpiry())`, default **2 seconds**, no `refreshAfterWrite`.

**Root cause:** Spring's `@Cacheable` without `sync=true` performs a non-atomic check-then-act: each thread independently checks the cache, finds it empty after expiry, and proceeds to invoke the underlying repository method. Caffeine's `expireAfterWrite` provides no stale-while-revalidate behavior and no built-in thundering-herd protection when accessed through Spring's caching abstraction. All N concurrent threads that arrive after expiry will all execute the SQL query simultaneously.

**Failed assumption:** The design assumes the cache will absorb concurrent load, but the 2-second TTL combined with the absence of `sync=true` means the protection collapses entirely at every expiry boundary.

### Impact Explanation

Each `getNodes()` call pages through the address book in chunks of `pageSize=10` (default). For a network with 30 nodes, each call issues 3 sequential DB queries. An attacker holding C connections × 5 calls/connection = 5C concurrent requests will cause 15C simultaneous SQL queries at every 2-second boundary. With C=100 connections (trivially achievable), this is 1500 simultaneous queries every 2 seconds, exhausting the database connection pool and causing query timeouts or OOM on the DB server. The `statementTimeout=10000ms` means each query holds a DB connection for up to 10 seconds during overload, amplifying pool exhaustion. Legitimate users of all gRPC services (including `subscribeTopic`) are denied service.

### Likelihood Explanation

No authentication is required to call `getNodes`. The gRPC port (5600) is publicly exposed. The only per-connection limit is `maxConcurrentCallsPerConnection=5` (`NettyProperties.java:14`), but there is no limit on the number of connections, no IP-based rate limiting, and no global concurrency cap on this endpoint. The attack is trivially scriptable: open many gRPC connections, synchronize `getNodes` calls to fire just after the 2-second mark, and repeat. The 2-second expiry makes the window predictable and the attack repeatable indefinitely.

### Recommendation

1. **Add `sync=true`** to the `@Cacheable` annotation on `findByConsensusTimestampAndNodeId`:
   ```java
   @Cacheable(
       cacheManager = ADDRESS_BOOK_ENTRY_CACHE,
       cacheNames = CACHE_NAME,
       sync = true,
       unless = "@spelHelper.isNullOrEmpty(#result)")
   ```
   This causes Spring to use `Cache.get(key, Callable)`, which Caffeine implements with per-key locking so only one thread computes the value while others wait.

2. **Switch to `refreshAfterWrite`** in `CacheConfiguration.addressBookEntryCache()` instead of (or in addition to) `expireAfterWrite`, so stale entries are served while a single background thread refreshes the value.

3. **Add a global connection or request rate limit** on the gRPC server for the `getNodes` RPC, analogous to the `ThrottleManagerImpl` used in the web3 module.

### Proof of Concept

```python
import grpc, threading, time
from com.hedera.mirror.api.proto import network_service_pb2_grpc, network_service_pb2
from proto.services import basic_types_pb2

TARGET = "mirror.node.host:5600"
NUM_CONNECTIONS = 100
CALLS_PER_CONN = 5

def flood():
    channel = grpc.insecure_channel(TARGET)
    stub = network_service_pb2_grpc.NetworkServiceStub(channel)
    req = network_service_pb2.AddressBookQuery(
        file_id=basic_types_pb2.FileID(fileNum=102))
    try:
        list(stub.getNodes(req))  # consume stream
    except Exception:
        pass

# Wait for cache to be warm, then fire all requests simultaneously at expiry
time.sleep(2.1)  # align to expiry boundary
threads = [threading.Thread(target=flood)
           for _ in range(NUM_CONNECTIONS * CALLS_PER_CONN)]
for t in threads: t.start()
for t in threads: t.join()
# Repeat every 2 seconds; observe DB connection pool exhaustion in server logs
```