# 4. No cloud SDK outside adapters

## Status

Deprecated

## Context

Cloud SDK calls were scattered across the codebase.

## Decision

Cloud provider SDKs may be imported only from the `adapters/` package.

## Consequences

Business logic stays portable between providers.
