# 2. Cloud SDKs live in adapters

## Status

Accepted

## Context

Cloud SDK calls were scattered across the code.

## Decision

No cloud SDK outside adapters/.

## Consequences

Storage code goes through the adapters package.
