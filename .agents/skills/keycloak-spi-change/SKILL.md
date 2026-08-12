---
name: keycloak-spi-change
description: >-
  Change Keycloak SPI event-listener behavior in this repo: update provider
  code and unit tests, keep LOGIN-only/async/best-effort constraints, and sync
  provider README Limitations. Use when editing last-login-timestamp listener
  or factory behavior.
---

# Keycloak SPI change

## When to use

Adding or changing event-listener behavior under `providers/`, especially `last-login-timestamp`.

## Instructions

1. Read the current listener/factory and matching tests before editing.
2. Prefer public Keycloak APIs; keep SPI deps `provided`. Do not add private Keycloak helpers beyond the events SPI already used.
3. Preserve product constraints unless the user explicitly expands them:
   - `EventType.LOGIN` only
   - after-commit / async non-blocking writes
   - best-effort updates with WARN-only failures
   - advisory (non-audit) attribute semantics
4. Update or add Mockito unit tests for new branches (filtering, write/skip, validation, logging allowlist).
5. Update `providers/<name>/README.md` Overview / How it works / Limitations / Configuration to match the new behavior.
6. Run `mvn -B spotless:apply`, then `mvn -B test`, then `mvn -B verify -DskipTests`.
7. Do not change Keycloak support versions in this skill; use `bump-keycloak-matrix` for that.
