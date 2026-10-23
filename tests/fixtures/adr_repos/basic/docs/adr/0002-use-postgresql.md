# 2. Use PostgreSQL as the only datastore

Date: 2026-01-12

## Status

Accepted

## Context

Several teams want different databases. Operating many datastores is costly.

## Decision

PostgreSQL is the only datastore.

No service may add another database, cache-as-database or document store
without a new ADR that supersedes this one.

## Consequences

Teams that need search use PostgreSQL full-text search first.
