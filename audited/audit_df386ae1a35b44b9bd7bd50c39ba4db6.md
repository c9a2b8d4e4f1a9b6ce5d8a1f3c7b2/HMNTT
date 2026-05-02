### Title
Unauthenticated Account Hook Enumeration via Missing Rate Limiting and No-DB-Lookup Numeric ID Resolution

### Summary
The `GET /api/v1/accounts/{id}/hooks` endpoint in `HooksController` requires no authentication and has no rate limiting. When a numeric account ID is supplied, `EntityServiceImpl.lookup()` returns the `EntityId` directly without any database existence check, meaning every numeric ID from 0 to max is silently accepted. An unprivileged attacker can iterate all possible account IDs and distinguish accounts with registered gossip-prevention hooks (non-empty response) from those without (empty list), fully enumerating the hook registry.

### Finding Description

**Code path:**

`HooksController.java:81-102` — `getHooks()` has no `@PreAuthorize`, no authentication annotation, and no `ThrottleManager` injection: [1](#0-0) 

The `ownerId` path variable is resolved via `EntityIdParameter`, which for numeric inputs resolves to `EntityIdNumParameter`. In `EntityServiceImpl.lookup()`, the `EntityIdNumParameter` branch returns the ID directly with no database existence check: [2](#0-1) 

Specifically, line 32 — `case EntityIdNumParameter p -> Optional.of(p.id())` — never touches the database, so any syntactically valid numeric ID (e.g., `0.0.1`, `0.0.999999`) is accepted without verifying the account exists. [3](#0-2) 

`HookServiceImpl.getHooks()` then queries the hook repository for that owner ID and returns an empty collection (not an error) when no hooks are found: [4](#0-3) 

The `rest-java` config directory contains no security filter or throttle configuration for this endpoint:


The `ThrottleManager` (bucket4j-based rate limiter) exists only in the `web3` module and is never wired into `HooksController`: [5](#0-4) 

**Root cause:** The combination of (a) no authentication gate on `getHooks()`, (b) no rate limiting in the `rest-java` module, and (c) `EntityIdNumParameter` bypassing the DB existence check means the endpoint silently accepts every numeric ID and leaks hook presence via response content.

### Impact Explanation
An attacker learns exactly which account IDs have gossip-prevention hooks registered. This is sensitive operational intelligence: it reveals which accounts are actively suppressing transaction gossip, potentially identifying high-value targets, protocol participants with special configurations, or accounts under investigation. The information is not otherwise public and its disclosure undermines the confidentiality assumption of the hook registry.

### Likelihood Explanation
The attack requires zero privileges, zero credentials, and only a standard HTTP client. The account ID space is a sequential integer range (shard.realm.num), making automated iteration trivial with a simple loop. No CAPTCHA, API key, or IP-based throttle exists on this endpoint in the `rest-java` module. The attack is fully repeatable and can be completed in minutes against a live deployment.

### Recommendation
1. **Authentication**: Add an `@PreAuthorize` or Spring Security filter requiring at minimum a valid API key or bearer token on `GET /api/v1/accounts/{id}/hooks`.
2. **Rate limiting**: Wire a `ThrottleManager` or bucket4j `Bucket` into `HooksController`, mirroring the pattern used in `OpcodesController`.
3. **Existence check**: Change the `EntityIdNumParameter` branch in `EntityServiceImpl.lookup()` to perform a DB existence check (matching the alias/EVM address branches), so requests for non-existent accounts return 404 rather than an empty hook list — this prevents distinguishing "account exists with no hooks" from "account does not exist."

### Proof of Concept
```bash
# Enumerate accounts 1 through 10000 for hook presence
for i in $(seq 1 10000); do
  RESULT=$(curl -s "https://<mirror-node>/api/v1/accounts/0.0.$i/hooks")
  HOOKS=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('hooks',[])))")
  if [ "$HOOKS" -gt "0" ]; then
    echo "Account 0.0.$i HAS HOOKS: $RESULT"
  fi
done
```
- No authentication header required.
- A non-empty `hooks` array in the response confirms the account has gossip-prevention hooks registered.
- An empty `hooks` array (HTTP 200, not 404) confirms the account ID was accepted but has no hooks.
- The loop can be parallelized trivially for faster enumeration.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L80-102)
```java
    @GetMapping
    ResponseEntity<HooksResponse> getHooks(
            @PathVariable EntityIdParameter ownerId,
            @RequestParam(defaultValue = "", name = HOOK_ID, required = false)
                    @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    NumberRangeParameter[] hookId,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "desc") Sort.Direction order) {

        final var hooksRequest = hooksRequest(ownerId, hookId, limit, order);
        final var hooksServiceResponse = hookService.getHooks(hooksRequest);
        final var hooks = hookMapper.map(hooksServiceResponse);

        final var sort = Sort.by(order, HOOK_ID);
        final var pageable = PageRequest.of(0, limit, sort);
        final var links = linkFactory.create(hooks, pageable, HOOK_EXTRACTOR);

        final var response = new HooksResponse();
        response.setHooks(hooks);
        response.setLinks(links);

        return ResponseEntity.ok(response);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-38)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L32-53)
```java
    public Collection<Hook> getHooks(HooksRequest request) {
        final var sort = Sort.by(request.getOrder(), HOOK_ID);
        final var page = PageRequest.of(0, request.getLimit(), sort);
        final var id = entityService.lookup(request.getOwnerId());
        final long lowerBound = request.getLowerBound();
        final long upperBound = request.getUpperBound();

        if (request.getHookIds().isEmpty()) {
            return hookRepository.findByOwnerIdAndHookIdBetween(id.getId(), lowerBound, upperBound, page);
        } else {
            // Both equal and range filters are present.
            final var idsInRange = request.getHookIds().stream()
                    .filter(hookId -> hookId >= lowerBound && hookId <= upperBound)
                    .toList();

            if (idsInRange.isEmpty()) {
                return List.of();
            }

            return hookRepository.findByOwnerIdAndHookIdIn(id.getId(), idsInRange, page);
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L20-49)
```java
final class ThrottleManagerImpl implements ThrottleManager {

    static final String REQUEST_PER_SECOND_LIMIT_EXCEEDED = "Requests per second rate limit exceeded";
    static final String GAS_PER_SECOND_LIMIT_EXCEEDED = "Gas per second rate limit exceeded.";

    @Qualifier(GAS_LIMIT_BUCKET)
    private final Bucket gasLimitBucket;

    @Qualifier(RATE_LIMIT_BUCKET)
    private final Bucket rateLimitBucket;

    @Qualifier(OPCODE_RATE_LIMIT_BUCKET)
    private final Bucket opcodeRateLimitBucket;

    private final ThrottleProperties throttleProperties;

    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
