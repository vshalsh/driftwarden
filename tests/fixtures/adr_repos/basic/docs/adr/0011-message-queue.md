# 11. Use RabbitMQ for messaging

Date: 2025-11-02

## Status

Superseded by [ADR-0003](0003-event-bus.md)

## Context

Services needed asynchronous messaging.

## Decision

We will use RabbitMQ as the message broker.

## Consequences

Operations must run a RabbitMQ cluster.
