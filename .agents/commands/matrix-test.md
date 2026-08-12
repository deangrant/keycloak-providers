# Matrix test

Spot-check unit tests against more than one Keycloak version from the CI matrix.

## Steps

1. Read the default from root `pom.xml` (`keycloak.version`) and the matrix from `.github/workflows/test.yml`.

2. Run tests for the POM default and one older matrix version (prefer the oldest listed, currently `26.6.4`):

```bash
mvn -B test -Dkeycloak.version=26.7.1
mvn -B test -Dkeycloak.version=26.6.4
```

Replace `26.7.1` with the current POM default if it differs.

3. Report pass/fail per version. If only one version fails, note likely SPI surface drift before proposing code changes.

4. Do not claim full matrix coverage unless every matrix version was run.
