### Title
Unbounded Base32 Alias Input Causes Memory Exhaustion (OOM) in GraphQL Service

### Summary
The `alias` field in `AccountInput` is validated only by a character-set regex (`^[A-Z2-7]+$`) with no upper-length bound. An unauthenticated attacker can submit arbitrarily long valid base32 strings that pass this check, causing `decodeBase32()` to allocate a proportionally large byte array on every request. Flooding the service with concurrent such requests can exhaust JVM heap and crash the GraphQL process.

### Finding Description
**Exact code path:**

In `graphql/src/main/resources/graphql/account.graphqls` line 90, the `alias` field is declared as:
```
alias: String @Pattern(regexp: "^[A-Z2-7]+$")
``` [1](#0-0) 

The `@Pattern` directive (defined in `directive.graphqls`) only validates that characters belong to the base32 alphabet. There is no `@Size`, `maxLength`, or any upper-bound quantifier in the regex (it uses `+`, meaning one or more, unbounded). [2](#0-1) 

After passing validation, the string flows to `EntityServiceImpl.getByAliasAndType()` at line 30:
```java
return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
``` [3](#0-2) 

Which calls `GraphQlUtils.decodeBase32()` at line 84:
```java
public static byte[] decodeBase32(String base32) {
    return BASE32.decode(base32);
}
``` [4](#0-3) 

Apache Commons Codec's `Base32.decode()` allocates a `byte[]` of approximately `(inputLength * 5) / 8` bytes — for a 10 MB input string, that is ~6.25 MB per request, all on the JVM heap.

**Root cause:** The `@Pattern` directive validates character set only. No length constraint exists anywhere in the input validation chain for the `alias` field.

**Why existing checks fail:** The `evmAddress` field uses a fixed-length pattern `^(0x)?[a-fA-F0-9]{40}$` (exactly 40 chars), bounding its allocation. The `alias` pattern `^[A-Z2-7]+$` has no upper bound. Compare with the REST Java service's `EntityIdAliasParameter`, which enforces `[A-Z2-7]{40,70}` — a hard cap of 70 characters — before decoding. [5](#0-4) 

### Impact Explanation
Each malicious request allocates megabytes of heap. With concurrent requests (e.g., 100 threads each sending a 10 MB alias string), the JVM heap is exhausted, triggering `OutOfMemoryError` and killing the GraphQL service process. This constitutes a complete denial of service of the GraphQL endpoint — an unauthenticated network-level shutdown of that service component.

### Likelihood Explanation
No authentication is required. The attacker only needs HTTP access to the GraphQL endpoint. The payload is trivially constructed (a long string of `A` characters passes `^[A-Z2-7]+$`). The attack is repeatable and automatable with any HTTP client. The GraphQL HTTP body size limit (if any, e.g., Spring's default `max-http-request-header-size` or body limits) is the only potential mitigating factor, but no such limit is enforced in the application code itself.

### Recommendation
1. **Add a length upper bound to the regex**: Change the `alias` pattern to match the REST Java service's constraint:
   ```
   alias: String @Pattern(regexp: "^[A-Z2-7]{1,70}$")
   ```
2. **Add a `@Size` directive** (or equivalent) to enforce a maximum string length at the GraphQL schema level.
3. **Add a length guard in `decodeBase32()`**:
   ```java
   public static byte[] decodeBase32(String base32) {
       if (base32 != null && base32.length() > 128) {
           throw new IllegalArgumentException("alias too long");
       }
       return BASE32.decode(base32);
   }
   ```
4. **Configure a global HTTP request body size limit** at the Spring/web server level as a defense-in-depth measure.

### Proof of Concept
```python
import requests, threading

# 8 million valid base32 chars → ~5 MB decoded byte array per request
alias = "A" * 8_000_000
query = f'{{ account(input: {{ alias: "{alias}" }}) {{ id }} }}'

def send():
    requests.post("http://<graphql-host>/graphql",
                  json={"query": query},
                  timeout=30)

threads = [threading.Thread(target=send) for _ in range(100)]
for t in threads: t.start()
for t in threads: t.join()
# Result: JVM OOM / GraphQL service process crash
```

### Citations

**File:** graphql/src/main/resources/graphql/account.graphqls (L89-90)
```text
    "A RFC 4648 Base32, with the trailing '=' characters removed, string that represents an account alias."
    alias: String @Pattern(regexp: "^[A-Z2-7]+$")
```

**File:** graphql/src/main/resources/graphql/directive.graphqls (L5-7)
```text
"Validation directive that ensures the argument or input value matches the given regular expression."
directive @Pattern(regexp : String! =".*", message : String = "graphql.validation.Pattern.message")
on ARGUMENT_DEFINITION | INPUT_FIELD_DEFINITION
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-31)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java (L83-85)
```java
    public static byte[] decodeBase32(String base32) {
        return BASE32.decode(base32);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdAliasParameter.java (L13-14)
```java
    public static final String ALIAS_REGEX = "^((\\d{1,5})\\.)?((\\d{1,5})\\.)?([A-Z2-7]{40,70})$";
    public static final Pattern ALIAS_PATTERN = Pattern.compile(ALIAS_REGEX);
```
