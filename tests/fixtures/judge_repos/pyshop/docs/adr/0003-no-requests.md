# 3. No requests library

## Status

Accepted

## Context

We moved to an async HTTP stack.

## Decision

Services must not import the requests library.

## Consequences

Use httpx in new code.
