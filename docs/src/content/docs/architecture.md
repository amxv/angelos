---
title: Architecture notes
description: A home for Angelos architecture as concrete implementation decisions land.
summary: Record system boundaries and invariants here as the codebase takes shape.
order: 2
category: Concepts
---

# Architecture notes

This page is deliberately sparse while Angelos is being scaffolded.

As implementation lands, use this section to explain durable system boundaries and invariants rather than speculative designs. Good candidates include:

- how agents identify and access mailboxes;
- how send and receive operations are represented;
- permission and authorization boundaries;
- delivery, retry, and idempotency behavior;
- persistence and retention rules;
- auditability and operator controls.

When a design is still unsettled, keep it in an implementation plan or issue rather than presenting it here as a shipped contract.
