---
status: accepted
date: 2026-02-01
deciders: platform team
---
# Use FastAPI for HTTP services

## Context and Problem Statement

We need one web framework for all HTTP services.

## Considered Options

* FastAPI
* Flask
* Django

## Decision Outcome

Chosen option: "FastAPI", because it gives typed request models and async support.

### Consequences

* Good, because request validation comes from Pydantic.
* Bad, because the team must learn async.
