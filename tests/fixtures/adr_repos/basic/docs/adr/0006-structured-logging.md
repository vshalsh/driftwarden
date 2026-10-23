# Use structured JSON logging

* Status: accepted
* Deciders: platform team
* Date: 2026-02-10

## Context and Problem Statement

Plain-text logs are hard to search across services.

## Considered Options

* structlog
* standard logging with a JSON formatter

## Decision Outcome

Chosen option: "structlog", because it produces JSON with bound context.

### Positive Consequences

* Logs are machine-searchable.

### Negative Consequences

* One more dependency.
