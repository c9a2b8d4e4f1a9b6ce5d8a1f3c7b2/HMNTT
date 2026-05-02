### Title
Unauthenticated Information Disclosure via `/api/v1/subscriber/{name}/{id}` Exposing Internal Error Maps and Operational State

### Summary
`SubscriberController.subscription()` at `GET /api/v1/subscriber/{name}/{id}` requires no authentication and returns a fully serialized `Scenario` object including its `errors` map (keyed by error type/message strings), elapsed time, count, rate, and status. No Spring Security configuration exists anywhere in the monitor module, meaning any unauthenticated HTTP client can enumerate all subscription scenarios and their failure details, including gRPC/Hedera error codes that reveal which subscription types are encountering authorization or connectivity failures.

### Finding Description
**Code location:**
- `monitor/src/main/java/org/hiero/mirror/monitor/subscribe/controller/SubscriberController.java`, lines 54–59 (`subscription()` method)
- `monitor/src/main/java/org/hiero/mirror/monitor/subscribe/Scenario.java`, line 25 (`getErrors()`)

`SubscriberController` is a `@RestController` with no `@PreAuthorize`, `@Secured`, or `@RolesAllowed` annotations on any method. [1](#0-0) 

No `SecurityConfig` or `WebSecurityConfig` class exists in the monitor module, and no `spring.security` properties are set in `monitor/src/main/resources/`. The entire `/api/v1/subscriber/**` surface is open to unauthenticated callers.

The `Scenario` interface serializes `getErrors()` (a `Map<String, Integer>` of error-type strings to counts), `getElapsed()`, `getCount()`, `getRate()`, and `getStatus()` directly into the HTTP response. [2](#0-1) 

The `getProperties()` method is `@JsonIgnore` and is not serialized, but all operational/error fields are. [3](#0-2) 

**Exploit flow:**
1. Attacker calls `GET /api/v1/subscriber` (no auth) to enumerate all scenario names and IDs. [4](#0-3) 
2. Attacker calls `GET /api/v1/subscriber/{name}/{id}` for each scenario to retrieve the full `Scenario` state. [5](#0-4) 
3. The `errors` map keys contain error class names or gRPC status strings (e.g., `UNAUTHENTICATED`, `PERMISSION_DENIED`, `UNAVAILABLE`) with their occurrence counts, revealing which subscription types are failing and why.
4. Elapsed time and rate fields reveal performance and stability characteristics of the mirror node connection.

**Why checks fail:** There are no checks. No authentication filter, no authorization annotation, no IP allowlist, no API key requirement exists anywhere in the monitor module for these endpoints. [6](#0-5) 

### Impact Explanation
An unauthenticated attacker gains continuous visibility into the internal operational state of the mirror node monitor: which subscription scenarios exist, which are failing, what error types are occurring (including auth-related gRPC status codes), and at what rate. This constitutes sensitive information disclosure about the infrastructure's security posture and failure modes. The `errors` map directly exposes the string representation of exceptions thrown during subscription, which can include Hedera network error codes indicating misconfigured credentials or authorization failures on specific transaction/topic subscriptions. This information can be used to identify weak points and craft targeted denial-of-service or replay attacks against specific subscription types.

### Likelihood Explanation
Exploitation requires only an HTTP client and knowledge of the endpoint path (which is standard REST convention and discoverable via the `GET /api/v1/subscriber` listing endpoint). No credentials, tokens, or special network position are required. The attack is trivially repeatable and automatable. Any internet-accessible deployment of the monitor service is fully exposed.

### Recommendation
1. Add Spring Security to the monitor module and require authentication (at minimum HTTP Basic or bearer token) for all `/api/v1/subscriber/**` endpoints.
2. If the API must remain open for internal tooling, restrict it to localhost or an internal network via firewall rules or a `management.server.address` binding.
3. Consider filtering the `errors` map before serialization to remove raw exception class names, replacing them with sanitized error codes.
4. Add an integration test asserting that unauthenticated requests to `/api/v1/subscriber` return `401`.

### Proof of Concept
```bash
# Step 1: Enumerate all subscription scenarios (no credentials needed)
curl -s http://<monitor-host>:<port>/api/v1/subscriber

# Step 2: Retrieve full state including error map for a specific scenario
curl -s http://<monitor-host>:<port>/api/v1/subscriber/myScenario/1

# Example response revealing auth failures:
# {
#   "count": 142,
#   "elapsed": "PT5M3S",
#   "errors": {
#     "io.grpc.StatusRuntimeException: UNAUTHENTICATED": 37,
#     "io.grpc.StatusRuntimeException: PERMISSION_DENIED": 12
#   },
#   "id": 1,
#   "name": "myScenario",
#   "protocol": "GRPC",
#   "rate": 0.47,
#   "status": "RUNNING",
#   "running": true
# }
```
No authentication, no special headers, no tokens required.

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/controller/SubscriberController.java (L26-66)
```java
@CustomLog
@RequestMapping("/api/v1/subscriber")
@RequiredArgsConstructor
@RestController
class SubscriberController {

    private final MirrorSubscriber mirrorSubscriber;

    @GetMapping
    public <T extends ScenarioProperties> Flux<Scenario<T, Object>> subscriptions(
            @RequestParam("protocol") Optional<ScenarioProtocol> protocol,
            @RequestParam("status") Optional<List<ScenarioStatus>> status) {
        return mirrorSubscriber
                .<Scenario<T, Object>>getSubscriptions()
                .filter(s -> !protocol.isPresent() || protocol.get() == s.getProtocol())
                .filter(s -> !status.isPresent() || status.get().contains(s.getStatus()))
                .switchIfEmpty(Mono.error(new NoSuchElementException()));
    }

    @GetMapping("/{name}")
    public <T extends ScenarioProperties> Flux<Scenario<T, Object>> subscriptions(
            @PathVariable("name") String name, @RequestParam("status") Optional<List<ScenarioStatus>> status) {
        Flux<Scenario<T, Object>> subscriptions = subscriptions(Optional.empty(), status);
        return subscriptions
                .filter(subscription -> subscription.getName().equals(name))
                .switchIfEmpty(Mono.error(new NoSuchElementException()));
    }

    @GetMapping("/{name}/{id}")
    public <T extends ScenarioProperties> Mono<Scenario<T, Object>> subscription(
            @PathVariable("name") String name, @PathVariable("id") int id) {
        Flux<Scenario<T, Object>> subscriptions = subscriptions(name, Optional.empty());
        return subscriptions.filter(s -> s.getId() == id).last();
    }

    @ResponseStatus(value = HttpStatus.NOT_FOUND, reason = "Not found")
    @ExceptionHandler(NoSuchElementException.class)
    void notFound() {
        // Error logging is done generically in LoggingFilter
    }
}
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/Scenario.java (L19-41)
```java
    long getCount();

    @JsonDeserialize(using = StringToDurationDeserializer.class)
    @JsonSerialize(using = DurationToStringSerializer.class)
    Duration getElapsed();

    Map<String, Integer> getErrors();

    int getId();

    default String getName() {
        return getProperties().getName();
    }

    @JsonIgnore
    P getProperties();

    ScenarioProtocol getProtocol();

    double getRate();

    ScenarioStatus getStatus();

```
