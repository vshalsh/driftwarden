# 3. Services communicate through the event bus

## Status

Proposed

## Context

Direct HTTP calls between services created tight coupling.

## Decision

Services talk to each other only through the event bus.
Synchronous service-to-service HTTP calls are not allowed.

## Consequences

Every service publishes domain events.
