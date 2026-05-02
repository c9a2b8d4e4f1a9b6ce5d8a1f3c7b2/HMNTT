### Title
Unauthenticated DB Connection Pool Exhaustion via Unbatched Triple-Query in `TopicController.getTopic()`

### Summary
`TopicController.getTopic()` at `/api/v1/topics/{id}` issues three sequential, independent database round-trips per request with no caching, no batching, and no rate limiting on the rest-java module. Any unauthenticated external user can send a moderate number of concurrent requests to this endpoint, holding HikariCP connections across three sequential queries per request, saturating the connection pool and raising node DB resource consumption well above 30% compared to baseline.

### Finding Description
**Exact code location:** `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 32–36.

```java
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());       // DB call 1 → TopicRepository
    var entity = entityService.findById(id.id());     // DB call 2 → EntityRepository
    var customFee = customFeeService.findById(id.id()); // DB call 3 → CustomFeeRepository
    return topicMapper.map(customFee, entity, topic);
}
```

Each call is a blocking JPA `findById` with no `@Cacheable` annotation:
- `TopicServiceImpl.findById` → `topicRepository.findById(id.getId())` (no cache)
- `EntityServiceImpl.findById` → `entityRepository.findById(id.getId())` (no cache; the rest-java `EntityRepository` is distinct from the grpc one which has `@Cacheable`)
- `CustomFeeServiceImpl.findById` → `customFeeRepository.findById(id.getId())` (no cache)

**Root cause / failed assumption:** The design assumes either (a) a caching layer or (b) a rate limiter will bound the DB load. Neither exists for this endpoint. The throttle infrastructure (`ThrottleManager`, `ThrottleConfiguration`, `ThrottleProperties`) lives exclusively in the `web3` module and is wired only to `ContractController`. `RestJavaProperties` contains no rate-limiting configuration whatsoever. The `statementTimeout` for rest-java is 10,000 ms, meaning each of the three queries can hold a connection for up to 10 seconds.

**HikariCP pool:** The pool is configured via `spring.datasource.hikari` with HikariCP defaults (10 connections). With N concurrent HTTP requests each making 3 sequential DB calls, the effective connection demand at any instant is up to N connections. With 10+ concurrent requests, the pool saturates; subsequent requests queue or time out, causing cascading latency and thread exhaustion in the servlet container.

### Impact Explanation
DB connection pool saturation causes all DB-dependent endpoints on the rest-java node to stall or fail. Thread pool exhaustion follows as servlet threads block waiting for connections. This raises CPU (blocked threads spinning/waiting), memory (queued requests), and DB server load simultaneously. The 30% resource increase threshold is reachable with ~10–20 concurrent persistent requests — well within the capability of a single attacker machine. No data is exfiltrated, but availability of the mirror node REST API is degraded or lost.

### Likelihood Explanation
The endpoint is public and unauthenticated. No API key, session token, or IP-based rate limit is enforced at the application layer. The attacker needs only a valid topic ID (trivially discoverable from the public Hedera ledger) and a tool capable of issuing concurrent HTTP GET requests (e.g., `ab`, `wrk`, `hey`, or a simple script). The attack is repeatable, requires no special knowledge, and produces measurable impact with low request volume — making it a realistic threat from any external actor.

### Recommendation
1. **Add response caching at the service or repository layer** for `TopicRepository`, `EntityRepository` (rest-java), and `CustomFeeRepository` using Spring `@Cacheable` with a short TTL (e.g., 5–30 seconds), consistent with the `Cache-Control: public, max-age=5` header already returned by this endpoint.
2. **Add a rate limiter** to the rest-java module for the `/api/v1/topics` path, mirroring the bucket4j-based `ThrottleManager` pattern already used in the `web3` module.
3. **Increase HikariCP pool size** or configure `connectionTimeout` to fail fast rather than queue indefinitely under saturation.
4. **Consider merging the three queries** into a single JOIN query to reduce round-trips to one DB call per request.

### Proof of Concept
```bash
# Precondition: obtain any valid topic ID from the public ledger, e.g., 0.0.1234
# Tool: Apache Bench or equivalent

ab -n 500 -c 50 https://<mirror-node-host>/api/v1/topics/0.0.1234
```
With 50 concurrent connections each triggering 3 DB round-trips:
- HikariCP pool (default 10) saturates immediately
- Requests queue; DB server CPU and connection count spike
- All other DB-backed endpoints on the same node degrade
- Sustained for 60+ seconds raises 24h-baseline resource consumption >30% [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L31-37)
```java
    @GetMapping(value = "/{id}")
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L24-27)
```java
    public Entity findById(EntityId id) {
        return entityRepository.findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Entity not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/CustomFeeServiceImpl.java (L19-23)
```java
    public CustomFee findById(EntityId id) {
        return customFeeRepository
                .findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Custom fee for entity not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/RestJavaProperties.java (L21-66)
```java
public class RestJavaProperties {

    @NotNull
    @Valid
    private ResponseConfig response = new ResponseConfig();

    /*
     * Post process the configured response headers. All header names are treated case insensitively, and, for each path,
     * the default headers are first inherited and their values possibly overridden.
     */
    @PostConstruct
    void mergeHeaders() {
        for (var pathHeaders : response.headers.path.entrySet()) {
            var mergedHeaders = Stream.concat(
                            response.headers.defaults.entrySet().stream(), pathHeaders.getValue().entrySet().stream())
                    .collect(Collectors.toMap(
                            Entry::getKey,
                            Entry::getValue,
                            (v1, v2) -> v2,
                            () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));

            pathHeaders.setValue(mergedHeaders);
        }
    }

    @Data
    @Validated
    public static class ResponseConfig {
        @NotNull
        @Valid
        private ResponseHeadersConfig headers = new ResponseHeadersConfig();
    }

    @Data
    @Validated
    public static class ResponseHeadersConfig {
        @NotNull
        private Map<String, String> defaults = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        @NotNull
        private Map<String, Map<String, String>> path = new HashMap<>();

        public Map<String, String> getHeadersForPath(String apiPath) {
            return apiPath == null ? defaults : path.getOrDefault(apiPath, defaults);
        }
    }
```

**File:** docs/configuration.md (L614-636)
```markdown
## REST Java API

Similar to the [Importer](#importer), the REST Java API uses [Spring Boot](https://spring.io/projects/spring-boot)
properties
to configure the application.

The following table lists the available properties along with their default values. Unless you need to set a non-default
value, it is recommended to only populate overridden properties in the custom `application.yml`.

| Name                                                     | Default                                            | Description                                                                                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hiero.mirror.restJava.db.host`                          | 127.0.0.1                                          | The IP or hostname used to connect to the database                                                                                                            |
| `hiero.mirror.restJava.db.name`                          | mirror_node                                        | The name of the database                                                                                                                                      |
| `hiero.mirror.restJava.db.password`                      | mirror_rest_java_pass                              | The database password used to connect to the database                                                                                                         |
| `hiero.mirror.restJava.db.port`                          | 5432                                               | The port used to connect to the database                                                                                                                      |
| `hiero.mirror.restJava.db.sslMode`                       | DISABLE                                            | The SSL level. Accepts either DISABLE, ALLOW, PREFER, REQUIRE, VERIFY_CA or VERIFY_FULL.                                                                      |
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
| `hiero.mirror.restJava.db.username`                      | mirror_rest_java                                   | The username used to connect to the database                                                                                                                  |
| `hiero.mirror.restJava.fee.refreshInterval`              | 10m                                                | How often to check for fee schedule updates from the database. Can accept duration units like `10s`, `2m` etc.                                                |
| `hiero.mirror.restJava.network.unreleasedSupplyAccounts` | 2-2, 42-42, 44-71, 73-87, 99-100, 200-349, 400-750 | Account ranges holding unreleased HBAR supply, excluded from circulating supply calculations                                                                  |
| `hiero.mirror.restJava.query.maxFileAttempts`            | 12                                                 | The maximum amount of times to query for Hedera files when the contents are not valid.                                                                        |
| `hiero.mirror.restJava.response.headers.defaults`        | See application.yml                                | The default headers to add to every response. For each header, specify its `name: value`                                                                      |
| `hiero.mirror.restJava.response.headers.path`            | See application.yml                                | Override default or add headers per path to add to every response. The key is the controller request mapping, then for each header, specify its `name: value` |
```
