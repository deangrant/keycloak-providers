---
name: dependabot-triage
description: >-
  Triage Dependabot PRs for this Maven/GitHub Actions repo: decide safe plugin
  bumps versus changes that need Keycloak matrix or README updates. Use when
  reviewing Dependabot PRs or weekly dependency alerts.
---

# Dependabot triage

## When to use

Reviewing Dependabot PRs or deciding whether a dependency bump is safe to merge.

## Instructions

1. Identify ecosystem from the PR (`maven` vs `github-actions`) and the changed coordinates/versions.
2. Classify impact:
   - **Low risk:** patch/minor bumps to build plugins (Spotless, Enforcer, Surefire, compiler), JUnit, Mockito, or pinned action SHAs that stay on the same major action—run `/lint` and `/test`.
   - **Needs matrix/docs care:** any change touching `keycloak.version`, Keycloak artifacts, or CI matrix entries—follow `bump-keycloak-matrix` and re-check READMEs.
   - **High caution:** Error Prone major bumps, Java toolchain changes, or anything forcing a Java version below/above 21.
3. Check Dependabot schedule/limits in `.github/dependabot.yml` only if the PR volume or grouping is the issue; do not loosen limits casually.
4. For Actions PRs, keep pins as full commit SHAs (no floating tags) when updating.
5. Before approving, run:

```bash
mvn -B spotless:apply
mvn -B verify -DskipTests
mvn -B test
```

6. Report: merge recommendation, required follow-ups (matrix/docs), and commands already run.
