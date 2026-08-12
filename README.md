# Keycloak Providers

Maven multi-module repository of [Keycloak](https://www.keycloak.org/) **SPI provider JARs**. The root POM (`me.deangrant.keycloak:keycloak-providers`) is an aggregator (`packaging` `pom`); each provider lives under `providers/<name>/` as its own module and produces a deployable JAR for Keycloak’s `providers/` directory.

Providers compile against Keycloak server SPI artifacts (`keycloak-server-spi`, `keycloak-server-spi-private`, `keycloak-core`) and JBoss Logging with Maven scope **`provided`**—Keycloak supplies those APIs at runtime. Modules register factories via `META-INF/services` (Java `ServiceLoader`). There are no Maven profiles for Keycloak versions; the single override point is the root property `keycloak.version`.

## Requirements

- JDK **21** (`maven.compiler.release` / Enforcer `[21,)`)
- Maven **3.9+** (Enforcer `[3.9,)`)

## Supported Keycloak versions

Default compile target: **26.7.1** (`keycloak.version` in the root POM).

CI recompiles and runs the **unit** suite (JUnit 5 + Mockito; no Testcontainers / Failsafe ITs) against:

- `26.7.1`
- `26.6.4`

Versions outside this set (including other majors) are unsupported unless added to the CI matrix. Override locally or in CI with:

```bash
mvn -B test -Dkeycloak.version=<version>
```

## Providers

| Provider | SPI | Description |
|----------|-----|-------------|
| [last-login-timestamp](providers/last-login-timestamp/) | `eventsListener` (`EventListenerProvider`) | On successful `LOGIN`, writes epoch-millis to a user attribute (default `lastLoginTimestamp`) after commit on a background pool—advisory, best-effort, non-blocking for auth |

Provider-specific install, SPI config, and limitations are documented in each module README.

## Build

From the repository root:

```bash
mvn clean package
```

Each module JAR is written to `providers/<name>/target/` (for example `providers/last-login-timestamp/target/last-login-timestamp.jar`).

Build one module and its reactor dependencies:

```bash
mvn clean package -pl providers/last-login-timestamp -am
```

## Test

```bash
mvn -B test
```

Optional Keycloak SPI version: `-Dkeycloak.version=<version>` (same property CI uses for the matrix).

## Lint

Format sources and run the same checks as CI lint:

```bash
mvn -B spotless:apply
mvn -B verify -DskipTests
```

`verify -DskipTests` runs Maven Enforcer, compiles with Error Prone, and Spotless check (Google Java Format)—no Surefire.

## License

[MIT](LICENSE) © Dean Grant
