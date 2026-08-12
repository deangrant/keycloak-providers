# Test

Run the Maven unit test suite from the repository root.

## Steps

1. Run tests. If the user named a Keycloak version, pass it; otherwise use the POM default:

```bash
mvn -B test
```

or:

```bash
mvn -B test -Dkeycloak.version=<version>
```

2. Report a short Surefire summary: modules run, tests passed/failed/skipped, and failing class/method names with assertion messages when present.

3. If failures look Keycloak-API related, suggest re-running against another matrix version from CI (`26.7.1`, `26.6.4`) before changing production code.
