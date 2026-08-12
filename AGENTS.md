# Agent and contributor guidance

Structured conventions for AI agents and humans working in this repository. For
fuller context, see [README.md](README.md).

## Docs

- [`.agents/docs/ARCHITECTURE.md`](.agents/docs/ARCHITECTURE.md) — high-level system architecture and diagrams
- [DeepWiki](https://deepwiki.com/deangrant/keycloak-providers) — indexed project wiki (architecture, providers, build)
- [README.md](README.md) — repository layout, Keycloak version matrix, build/test/lint
- [providers/last-login-timestamp/README.md](providers/last-login-timestamp/README.md) — event-listener architecture, limitations, install/config
- [providers/magic-link/README.md](providers/magic-link/README.md) — magic link / continuation / email OTP authenticators, themes, factory-injected customization

## Rules

- [`.agents/rules/`](.agents/rules/) (symlinked from [`.cursor/rules`](.cursor/rules))
- [`.agents/rules/keycloak-spi.mdc`](.agents/rules/keycloak-spi.mdc) — always-on SPI policy (provided deps, LOGIN-only/best-effort, `keycloak.version`)
- [`.agents/rules/java-maven.mdc`](.agents/rules/java-maven.mdc) — Java 21, Spotless, verify/test after meaningful changes
- [`.agents/rules/docs-sync.mdc`](.agents/rules/docs-sync.mdc) — keep README Keycloak lists aligned with CI matrix and POM default

## Skills

- [`.agents/skills/`](.agents/skills/) (canonical path; not symlinked into `.cursor/skills`)
- [`.agents/skills/keycloak-spi-change/`](.agents/skills/keycloak-spi-change/) — change listener behavior with tests and provider README sync
- [`.agents/skills/bump-keycloak-matrix/`](.agents/skills/bump-keycloak-matrix/) — keep POM default, CI matrix, and READMEs in sync
- [`.agents/skills/dependabot-triage/`](.agents/skills/dependabot-triage/) — triage Maven/Actions Dependabot PRs
- [`.agents/skills/java-javadoc/`](.agents/skills/java-javadoc/) — write JavaDoc compatible with Spotless and Error Prone

## Commands

- [`.agents/commands/`](.agents/commands/) (symlinked from [`.cursor/commands`](.cursor/commands))
- `/lint` — Spotless apply then `mvn -B verify -DskipTests`
- `/test` — `mvn -B test` (optional `-Dkeycloak.version=…`)
- `/matrix-test` — spot-check POM default plus one other CI matrix version
- `/provider-readme` — align provider README with listener behavior after a change

## Hooks

- Config: [`.cursor/hooks.json`](.cursor/hooks.json)
- `beforeShellExecution` → [`.agents/hooks/block-destructive-git.sh`](.agents/hooks/block-destructive-git.sh) denies force-push / `git reset --hard`
- `afterFileEdit` → [`.agents/hooks/spotless-nudge.sh`](.agents/hooks/spotless-nudge.sh) reminds agents to format edited `*.java` files
