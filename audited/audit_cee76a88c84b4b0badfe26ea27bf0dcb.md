### Title
Unauthenticated Access to Any Account's Hooks via Alias Resolution in `getHooks()`

### Summary
The `GET /api/v1/accounts/{ownerId}/hooks` endpoint in `HooksController` performs no authentication or authorization check before returning hook data. Any unauthenticated caller can supply a Base32 alias (or numeric ID, or EVM address) as `ownerId`, which is resolved to a victim's internal entity ID via `EntityIdParameter.valueOf()` → `EntityIdAliasParameter.valueOfNullable()`, and the service returns all hooks belonging to that entity without any credential verification.

### Finding Description
**Code path:**

- `HooksController.java` lines 80–102: `getHooks()` accepts `@PathVariable EntityIdParameter ownerId` with no `@PreAuthorize`, no session check, and no ownership assertion.
- `EntityIdParameter.valueOf()` (lines 10–26) tries numeric, EVM address, then Base32 alias parsing in sequence — all three formats are accepted from any caller.
- `EntityIdAliasParameter.valueOfNullable()` (lines 17–38) decodes a Base32 string into `(shard, realm, alias)` with no caller identity check.
- `HookServiceImpl.getHooks()` (lines 32–53) calls `entityService.lookup(request.getOwnerId())` to resolve the alias to a concrete `id.getId()`, then queries `hookRepository.findByOwnerIdAndHookIdBetween(id.getId(), ...)` — returning all hooks for that resolved entity ID.

**Root cause:** The controller and service layers contain zero authentication or authorization logic. The assumption that only the account owner would know or supply their own `ownerId` is false — aliases are derivable from public keys, which are on-chain public data.

**Why existing checks fail:** No `SecurityConfig`, `@PreAuthorize`, filter chain, or ownership assertion exists anywhere in this flow. The only validation is input format validation (`@Size`, `@Positive`, `@Max`), which is irrelevant to authorization.

### Impact Explanation
An attacker can enumerate hooks (and their associated metadata) for any account on the network by iterating known aliases or numeric IDs. Hook data is tied to submitted transactions and may expose behavioral patterns, contract interaction history, or storage state that account owners consider private. The impact is unauthorized read access to sensitive per-account data at scale.

### Likelihood Explanation
No special privileges are required. Base32 aliases are derived from public keys, which are publicly visible on-chain. Any network participant can construct a valid alias for any account they observe. The attack is trivially repeatable via a simple HTTP GET with no credentials, making automated enumeration straightforward.

### Recommendation
1. Add authentication at the Spring Security filter level (e.g., require a valid bearer token or API key for `/api/v1/accounts/*/hooks`).
2. Add an authorization check in `getHooks()` to assert that the authenticated principal's entity ID matches the resolved `ownerId` before querying.
3. If hooks are intended to be public read data, document that explicitly and confirm no sensitive fields are exposed; otherwise enforce ownership.

### Proof of Concept
```
# Attacker observes victim's Base32 alias from on-chain data, e.g. ABCDEFGHIJKLMNOPQRSTU1234567890ABCDEFGHIJ

GET /api/v1/accounts/ABCDEFGHIJKLMNOPQRSTU1234567890ABCDEFGHIJ/hooks
Host: mirror-node.example.com
# No Authorization header, no session cookie

# Response: HTTP 200 with full list of hooks belonging to the victim's account
{
  "hooks": [ ... ],
  "links": { ... }
}
```

The alias is decoded by `EntityIdAliasParameter.valueOfNullable()`, resolved to the victim's entity ID by `entityService.lookup()`, and the repository returns all matching hooks — with no credential check at any step.