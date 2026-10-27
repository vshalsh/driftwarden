# 3. Database access

## Status

Accepted

## Context

SQL was spread over route handlers.

## Decision

Only src/db/ may import pg.

## Consequences

Routes call the db module.
