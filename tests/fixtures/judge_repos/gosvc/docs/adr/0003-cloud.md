# 3. Cloud SDK boundary

## Status

Accepted

## Context

AWS calls leaked into handlers.

## Decision

No cloud SDK outside internal/cloud/.

## Consequences

Handlers depend on interfaces.
