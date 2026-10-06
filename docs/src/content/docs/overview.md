---
title: Overview
description: What Angelos is, what this repository is for, and how the docs should grow with the project.
summary: Start here for the current project scope and documentation contract.
order: 1
category: Start
---

# Overview

Angelos is an agent-native email project. Its goal is to give agents a deliberate interface for working with email, including sending, receiving, and acting on messages as part of larger workflows.

The implementation is still being built. These docs intentionally avoid specifying APIs, storage choices, authentication flows, or permission models before those decisions exist in code.

## Documentation contract

Treat the documentation as part of the implementation:

- Add or update a guide when a user-facing workflow changes.
- Document important security and permission boundaries when they are introduced.
- Keep reference material aligned with real interfaces and behavior.
- Prefer examples that are tested against the current codebase.

## Where to go next

Read [Architecture notes](/docs/architecture) for the rules around documenting system design, or [Writing docs](/docs/writing-docs) before adding a new page.
