---
name: bump-keycloak-matrix
description: >-
  Keep Keycloak version default and CI matrix in sync across root POM,
  test workflow, and READMEs. Use when adding, removing, or changing supported
  Keycloak versions or the compile-target default.
---

# Bump Keycloak matrix

## When to use

Changing the default `keycloak.version` or the set of CI-tested Keycloak versions.

## Instructions

1. Update root `pom.xml` property `keycloak.version` when the compile default changes.
2. Update `.github/workflows/test.yml` matrix `keycloak-version` list to the supported set.
3. Update version lists in:
   - root `README.md` (default + supported list)
   - each provider README that states default/CI-tested Keycloak versions
4. Do not invent Maven profiles for versions; document `-Dkeycloak.version=<version>` only.
5. Verify with at least the new default and one other matrix version:

```bash
mvn -B test -Dkeycloak.version=<default>
mvn -B test -Dkeycloak.version=<other-matrix-version>
```

6. Summarize which files changed and which versions are now supported.
