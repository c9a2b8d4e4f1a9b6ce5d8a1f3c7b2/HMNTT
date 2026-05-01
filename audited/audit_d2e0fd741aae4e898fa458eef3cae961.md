### Title
Unauthenticated gRPC `getNodes` Endpoint Allows DB Connection Pool Exhaustion via Concurrent Requests

### Summary
The `getNodes` gRPC endpoint in `NetworkController` is publicly accessible with no authentication, rate limiting, or global concurrency cap. Each call drives `NetworkServiceImpl.page()` to repeatedly invoke `transactionOperations.execute()`, which acquires a HikariCP read-only DB connection per page. An attacker opening many TCP connections (each allowed 5 concurrent calls by `maxConcurrentCallsPerConnection`) can saturate the shared HikariCP pool, causing all subsequent `page()` calls to block indefinitely and rendering the gRPC service unavailable.

### Finding Description

**Exact code path:**

`NetworkController.getNodes()` (no auth/rate-limit guard) → `NetworkServiceImpl.getNodes()` → `Flux.defer(() -> page(context)).repeatWhen(...)` → `page()` → `transactionOperations.execute(t -> { ... })`. [1](#0-0) [2](#0-1) [3](#0-2) 

**Root cause — failed assumption:**

The only server-side concurrency control is `maxConcurrentCallsPerConnection = 5` (default), configured in `GrpcConfiguration` via `NettyProperties`. [4](#0-3) [5](#0-4) 

This limit is **per-connection**, not global. There is no cap on the total number of inbound TCP connections, no global concurrent-call semaphore, and no rate limiter on the gRPC module (the `ThrottleConfiguration`/`ThrottleManagerImpl` rate-limiting beans exist only in the `web3` module, not in `grpc`).

The `transactionOperations` bean is a plain `TransactionTemplate` wrapping the shared HikariCP pool (default `maximumPoolSize = 10`). [6](#0-5) [7](#0-6) 

Each `page()` call holds a HikariCP connection for the duration of the DB query. With `pageDelay = 250ms` and `pageSize = 10`, a single `getNodes(limit=0)` call issues one `page()` every 250ms until the address book is exhausted. [8](#0-7) 

**Exploit flow:**

1. Attacker opens N TCP connections to port 5600 (no authentication required, publicly documented endpoint).
2. On each connection, sends 5 concurrent `getNodes` RPCs with `file_id=102` and `limit=0`.
3. Total simultaneous `page()` calls in flight = N × 5.
4. Each `page()` call calls `transactionOperations.execute()`, which calls `HikariDataSource.getConnection()`.
5. With N × 5 > 10 (pool size), all pool slots are occupied; further `execute()` calls block on HikariCP's `connectionTimeout` (default 30 s).
6. The `Schedulers.boundedElastic()` threads used by `repeatWhen` pile up waiting for connections.
7. Legitimate `getNodes` and `subscribeTopic` calls that also need DB connections are starved.

### Impact Explanation

The gRPC mirror node becomes unable to serve any DB-backed request. Clients (SDKs, wallets, consensus nodes bootstrapping their address book) cannot retrieve node address book data. Because `getNodes` is the canonical HIP-21 mechanism for clients to discover network topology, sustained exhaustion prevents new clients from joining the network and disrupts existing clients that refresh their address book. This constitutes a denial-of-service against the mirror node's gRPC processing capability without requiring any privileged access.

### Likelihood Explanation

The attack requires only a TCP connection to port 5600 and knowledge of the public gRPC proto (documented in `docs/grpc/README.md` and the protobuf definition). No credentials, tokens, or special network position are needed. The attack is trivially scriptable with `grpcurl` or any gRPC client library. It is repeatable and sustainable: the attacker simply keeps connections open and streams `getNodes` indefinitely. A single attacker machine with modest bandwidth can open hundreds of TCP connections.

### Recommendation

1. **Add a global concurrent-call semaphore** in `NetworkServiceImpl.getNodes()` (e.g., a `Semaphore` or Reactor `flatMap(maxConcurrency)`) to cap total simultaneous `page()` executions regardless of connection count.
2. **Add per-IP or global rate limiting** on the gRPC server, analogous to the `ThrottleConfiguration` in the `web3` module, applied via a gRPC `ServerInterceptor`.
3. **Set `maxConnectionAge` and `maxConnectionAgeGrace`** on the `NettyServerBuilder` to recycle long-lived attacker connections.
4. **Explicitly configure `spring.datasource.hikari.maximum-pool-size`** in the gRPC module's `application.yml` and size it deliberately, so pool exhaustion behavior is predictable and monitored (the existing Prometheus alert `GrpcHighDBConnections` at 75% threshold is a good signal but does not prevent exhaustion).
5. Consider adding a **`limit` floor** so `limit=0` (unlimited) requests are rejected or capped at a safe maximum.

### Proof of Concept

```bash
# Open 4 connections, 5 concurrent streams each = 20 simultaneous page() calls
# (exceeds default HikariCP pool of 10)
for i in $(seq 1 20); do
  grpcurl -plaintext \
    -d '{"file_id": {"fileNum": 102}, "limit": 0}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.NetworkService/getNodes &
done
wait

# Legitimate request now blocks or times out:
grpcurl -plaintext \
  -d '{"file_id": {"fileNum": 102}, "limit": 1}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.NetworkService/getNodes
# Expected: hangs or returns UNAVAILABLE / DEADLINE_EXCEEDED
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L68-77)
```java
        return Flux.defer(() -> page(context))
                .repeatWhen(RepeatSpec.create(c -> !context.isComplete(), Long.MAX_VALUE)
                        .jitter(0.5)
                        .withFixedDelay(addressBookProperties.getPageDelay())
                        .withScheduler(Schedulers.boundedElastic()))
                .take(filter.getLimit() > 0 ? filter.getLimit() : Long.MAX_VALUE)
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Querying for address book: {}", filter))
                .doOnComplete(() -> log.info("Retrieved {} nodes from the address book", context.getCount()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/NetworkServiceImpl.java (L79-108)
```java
    private Flux<AddressBookEntry> page(AddressBookContext context) {
        return transactionOperations.execute(t -> {
            var addressBookTimestamp = context.getAddressBookTimestamp();
            var nodeStakeMap = context.getNodeStakeMap();
            var nextNodeId = context.getNextNodeId();
            var pageSize = addressBookProperties.getPageSize();
            var nodes = addressBookEntryRepository.findByConsensusTimestampAndNodeId(
                    addressBookTimestamp, nextNodeId, pageSize);
            var endpoints = new AtomicInteger(0);

            nodes.forEach(node -> {
                // Override node stake
                node.setStake(nodeStakeMap.getOrDefault(node.getNodeId(), 0L));
                // This hack ensures that the nested serviceEndpoints is loaded eagerly and voids lazy init exceptions
                endpoints.addAndGet(node.getServiceEndpoints().size());
            });

            if (nodes.size() < pageSize) {
                context.completed();
            }

            log.info(
                    "Retrieved {} address book entries and {} endpoints for timestamp {} and node ID {}",
                    nodes.size(),
                    endpoints,
                    addressBookTimestamp,
                    nextNodeId);
            return Flux.fromIterable(nodes);
        });
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L19-25)
```java
    @Bean
    @Qualifier("readOnly")
    TransactionOperations transactionOperationsReadOnly(PlatformTransactionManager transactionManager) {
        var transactionTemplate = new TransactionTemplate(transactionManager);
        transactionTemplate.setReadOnly(true);
        return transactionTemplate;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-34)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L61-95)
```java
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @Lazy
    DataSource dataSource(
            DataSourceProperties dataSourceProperties,
            HikariConfig hikariConfig,
            DatabaseWaiter databaseWaiter,
            ObjectProvider<JdbcConnectionDetails> detailsProvider) {

        var jdbcUrl = dataSourceProperties.determineUrl();
        var username = dataSourceProperties.determineUsername();
        var password = dataSourceProperties.determinePassword();

        final var connectionDetails = detailsProvider.getIfAvailable();
        if (connectionDetails != null) {
            jdbcUrl = connectionDetails.getJdbcUrl();
            username = connectionDetails.getUsername();
            password = connectionDetails.getPassword();
        }

        databaseWaiter.waitForDatabase(jdbcUrl, username, password);

        final var config = new HikariConfig();
        hikariConfig.copyStateTo(config);
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);

        return new HikariDataSource(config);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/AddressBookProperties.java (L33-37)
```java
    @NotNull
    private Duration pageDelay = Duration.ofMillis(250L);

    @Min(1)
    private int pageSize = 10;
```
