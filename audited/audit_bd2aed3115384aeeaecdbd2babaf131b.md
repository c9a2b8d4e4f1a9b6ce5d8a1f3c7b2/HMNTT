### Title
Unauthenticated IDOR in `getHooks()` Allows Bulk Data Exfiltration for Any Owner

### Summary
`HookServiceImpl.getHooks()` resolves the caller-supplied `ownerId` and executes a paginated database query without any authorization check to verify the caller is permitted to view hooks for that owner. Combined with the absence of a maximum-limit cap in `HooksRequest`, an unprivileged attacker can enumerate all hooks belonging to any arbitrary account in a single request.

### Finding Description
**Code path:**
- `HooksRequest.java` (lines 20–21): `limit` defaults to 25 with no `@Max` or `@Min` constraint annotation — the field is a plain `int` with no upper bound enforced at the DTO level.
- `HookServiceImpl.getHooks()` (lines 32–52): The method calls `entityService.lookup(request.getOwnerId())` to resolve the entity, then immediately passes `request.getLimit()` directly into `PageRequest.of(0, request.getLimit(), sort)` and fires the query against `hookRepository.findByOwnerIdAndHookIdBetween(id.getId(), ...)`.

**Root cause — two compounding failures:**
1. **No authorization gate**: After resolving the entity, there is zero check that the authenticated principal matches or has delegated access to `ownerId`. Any caller who can reach the endpoint can supply an arbitrary victim's entity ID.
2. **No limit cap**: `request.getLimit()` is used verbatim. An attacker can set `limit = Integer.MAX_VALUE` (or any large integer the DB will accept) to drain the entire hook table for the target owner in one round-trip.

**Why existing checks are insufficient:**
`entityService.lookup()` is a pure entity-resolution call — it confirms the entity exists but performs no access-control decision. No `@PreAuthorize`, `@Secured`, or manual principal comparison appears anywhere in the call chain visible in the codebase. [1](#0-0) [2](#0-1) 

### Impact Explanation
Any unauthenticated or low-privilege user can read the complete hook list of any account on the network. Hooks may contain sensitive configuration data (callback URLs, secrets, business logic triggers). The missing limit cap means a single HTTP request can return millions of rows, causing both data leakage and a denial-of-service condition on the database.

### Likelihood Explanation
Exploitation requires only the ability to send an HTTP request to the mirror-node REST API (publicly accessible by design) and knowledge of a target's entity ID (entity IDs are sequential integers, trivially enumerable). No credentials, special roles, or prior access are needed. The attack is fully repeatable and automatable.

### Recommendation
1. **Add authorization**: In `getHooks()`, after resolving the entity, assert that the authenticated principal equals `ownerId` or holds an explicit delegation. Use Spring Security's `@PreAuthorize("@authz.canReadHooks(#request.ownerId)")` or an equivalent inline check.
2. **Cap the limit**: Add `@Max(100)` (or your chosen page-size ceiling) to the `limit` field in `HooksRequest`, and enforce it with Bean Validation (`@Valid`) at the controller layer. Additionally add a hard guard in `getHooks()`: `int safeLimit = Math.min(request.getLimit(), MAX_PAGE_SIZE);`.

### Proof of Concept
```
# 1. Discover a victim's entity ID (sequential, public)
GET /api/v1/accounts  →  note victim accountId, e.g. 0.0.12345

# 2. Send unauthenticated request with max limit and victim ownerId
GET /api/v1/hooks?ownerId=0.0.12345&limit=2147483647&order=asc

# Expected (vulnerable) result:
# HTTP 200 with the full hook list for account 0.0.12345,
# no authentication or ownership check performed,
# database query unbounded by any server-side page cap.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L32-52)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HooksRequest.java (L17-21)
```java
    @Builder.Default
    private final Collection<Long> hookIds = List.of();

    @Builder.Default
    private final int limit = 25;
```
