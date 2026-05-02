All code references have been verified against the actual source. Here is the result:

---

Audit Report

## Title
Shared Unsynchronized `LinkedList` Between `ListReadableQueueState` and `ListWritableQueueState` Enables Cross-Request Queue Corruption in Concurrent EVM Simulations

## Summary
`MirrorNodeState` is a `@Named` Spring singleton that creates a single `new LinkedList<>()` at construction time as the backing store for `RecordCacheService`'s `TRANSACTION_RECEIPTS_STATE_ID`. Both `getReadableStates()` and `getWritableStates()` wrap this same `LinkedList` instance — the former in a `ListReadableQueueState`, the latter in a `ListWritableQueueState` — and cache both wrappers in `ConcurrentHashMap`s. Because `java.util.LinkedList` is not thread-safe, concurrent EVM simulations (`eth_call`, `eth_estimateGas`) that simultaneously read and mutate this shared queue can observe mid-mutation state, and committed writes from one simulation permanently pollute the queue for all subsequent simulations.

## Finding Description

**Verified code path:**

`MirrorNodeState.initQueueStates()` creates one `LinkedList` for the entire lifetime of the singleton bean: [1](#0-0) 

`getReadableStates()` wraps that same `queue` reference in a `ListReadableQueueState` and caches it via `computeIfAbsent`: [2](#0-1) 

`getWritableStates()` wraps the same `queue` reference in a `ListWritableQueueState` and caches it via `computeIfAbsent`: [3](#0-2) 

Both caches are `ConcurrentHashMap`s, so the same wrapper instances — and therefore the same `LinkedList` — are reused across all concurrent requests: [4](#0-3) 

**Direct unsynchronized mutation:**

`ListWritableQueueState.addToDataSource()` and `removeFromDataSource()` call `backingStore.add()` and `backingStore.remove()` directly on the `LinkedList` with no locking: [5](#0-4) 

`ListReadableQueueState.peekOnDataSource()` and `iterateOnDataSource()` call `backingStore.peek()` and `backingStore.iterator()` directly on the same `LinkedList` with no locking: [6](#0-5) 

These mutations are triggered at commit time via `MapWritableStates.commit()`, which calls `queue.commit()` on the `WritableQueueStateBase`, which in turn calls `addToDataSource()`/`removeFromDataSource()`: [7](#0-6) 

**State pollution across simulations (non-concurrent path):**

The `onCommit` callback registered in `getWritableStates()` only evicts the `readableStates` cache entry for `RecordCacheService.NAME`; it does **not** clear or reset the `LinkedList` itself: [8](#0-7) 

This means every element added to the queue by any simulation permanently accumulates in the shared `LinkedList`, making the queue grow unboundedly and causing every subsequent simulation to read stale receipts from prior simulations — even in the absence of concurrent access.

**Why existing checks are insufficient:**

The `ConcurrentHashMap` used for `readableStates` and `writableStates` protects only the map-level lookup. There is no `synchronized` block, `ReentrantReadWriteLock`, or thread-safe queue (e.g., `ConcurrentLinkedQueue`) anywhere in the queue state path. `java.util.LinkedList` is explicitly documented as not thread-safe: structural modifications (add/remove) while another thread holds an iterator cause `ConcurrentModificationException`, and non-structural concurrent access produces silently incorrect results.

## Impact Explanation
During concurrent EVM simulations, `RecordCacheService` reads the `TRANSACTION_RECEIPTS_STATE_ID` queue to determine transaction receipts that affect simulation context. If Thread A's simulation commits and calls `addToDataSource()`/`removeFromDataSource()` on the shared `LinkedList` while Thread B's simulation is iterating or peeking the same list, Thread B can observe a partially-mutated queue, causing the EVM simulation to operate on incorrect receipt state. This produces wrong gas estimates, wrong revert/success outcomes, or wrong return data. Additionally, because the `LinkedList` is never reset between simulations, writes from one simulation permanently corrupt the baseline state for all subsequent simulations, compounding the error over time.

## Likelihood Explanation
Any unprivileged user with network access to the mirror node's JSON-RPC endpoint can trigger this by sending two or more concurrent `eth_call` or `eth_estimateGas` requests. No authentication, special role, or privileged access is required. Under normal production load with multiple concurrent users, the race fires probabilistically without any deliberate attack. The state-pollution variant (stale receipts from prior simulations) fires on every simulation after the first one that writes to the queue, regardless of concurrency.

## Recommendation
1. Replace the `LinkedList` backing store with a thread-safe queue such as `java.util.concurrent.ConcurrentLinkedQueue`, or wrap all accesses in a `synchronized` block or `ReentrantReadWriteLock`.
2. Reset (clear) the `LinkedList` as part of the `onCommit` callback so that receipts written during one simulation do not persist into subsequent simulations. Alternatively, create a fresh `LinkedList` per-request rather than sharing a singleton instance.
3. Consider whether the `writableStates` cache for `RecordCacheService` should also be evicted on commit (currently only `readableStates` is evicted), to ensure a fresh `ListWritableQueueState` — and therefore a fresh buffer — is used for each simulation.

## Proof of Concept
```
// Two threads simultaneously call eth_call or eth_estimateGas.
// Both reach MapWritableStates.commit() at approximately the same time.
// Thread A calls ListWritableQueueState.addToDataSource(receiptA)
//   → backingStore.add(receiptA)  [no lock]
// Thread B calls ListReadableQueueState.iterateOnDataSource()
//   → backingStore.iterator()     [no lock]
// Thread A's structural modification invalidates Thread B's iterator
//   → ConcurrentModificationException thrown in Thread B's simulation, OR
//   → Thread B's peek()/iterator() returns a partially-written element,
//     causing the simulation to use incorrect receipt state.
//
// Even without concurrency:
// Simulation 1 commits receiptA → backingStore now contains [receiptA]
// onCommit removes readableStates entry but does NOT clear backingStore
// Simulation 2 reads the queue → sees [receiptA] from Simulation 1
//   → Simulation 2 operates on stale/incorrect receipt state.
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/MirrorNodeState.java (L52-53)
```java
    private final Map<String, ReadableStates> readableStates = new ConcurrentHashMap<>();
    private final Map<String, WritableStates> writableStates = new ConcurrentHashMap<>();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/MirrorNodeState.java (L67-78)
```java
    public ReadableStates getReadableStates(@NonNull String serviceName) {
        return readableStates.computeIfAbsent(serviceName, s -> {
            final var serviceStates = this.states.get(s);
            if (serviceStates == null) {
                return new MapReadableStates(new HashMap<>());
            }
            final Map<Integer, Object> data = new ConcurrentHashMap<>();
            for (final var entry : serviceStates.entrySet()) {
                final var stateId = entry.getKey();
                final var state = entry.getValue();
                if (state instanceof Queue<?> queue) {
                    data.put(stateId, new ListReadableQueueState<>(serviceName, stateId, queue));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/MirrorNodeState.java (L91-102)
```java
    public WritableStates getWritableStates(@NonNull String serviceName) {
        return writableStates.computeIfAbsent(serviceName, s -> {
            final var serviceStates = states.get(s);
            if (serviceStates == null) {
                return new EmptyWritableStates();
            }
            final Map<Integer, Object> data = new ConcurrentHashMap<>();
            for (final var entry : serviceStates.entrySet()) {
                final var stateId = entry.getKey();
                final var state = entry.getValue();
                if (state instanceof Queue<?> queue) {
                    data.put(stateId, new ListWritableQueueState<>(serviceName, stateId, queue));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/MirrorNodeState.java (L114-114)
```java
            return new MapWritableStates(data, () -> readableStates.remove(serviceName));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/MirrorNodeState.java (L170-172)
```java
    private void initQueueStates() {
        states.put(RecordCacheService.NAME, new HashMap<>(Map.of(TRANSACTION_RECEIPTS_STATE_ID, new LinkedList<>())));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/core/ListWritableQueueState.java (L30-38)
```java
    @Override
    protected void addToDataSource(@NonNull E element) {
        backingStore.add(element);
    }

    @Override
    protected void removeFromDataSource() {
        backingStore.remove();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/core/ListReadableQueueState.java (L32-42)
```java
    @Nullable
    @Override
    protected E peekOnDataSource() {
        return backingStore.peek();
    }

    @NonNull
    @Override
    protected Iterator<E> iterateOnDataSource() {
        return backingStore.iterator();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/core/MapWritableStates.java (L97-110)
```java
    public void commit() {
        states.values().forEach(state -> {
            switch (state) {
                case WritableKVStateBase kv -> kv.commit();
                case WritableSingletonStateBase singleton -> singleton.commit();
                case WritableQueueStateBase queue -> queue.commit();
                default ->
                    throw new IllegalStateException(
                            "Unknown state type " + state.getClass().getName());
            }
        });
        if (onCommit != null) {
            onCommit.run();
        }
```
