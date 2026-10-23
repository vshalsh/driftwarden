# Cache read models in memory

* Status: proposed

## Context and Problem Statement

Read endpoints repeat the same queries.

## Decision Drivers

* latency
* no extra infrastructure

## Decision Outcome

Chosen option: "in-process LRU cache", because it needs no new datastore.

## Consequences

Caches are per process and may be briefly stale.
