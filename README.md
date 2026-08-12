# Keycloak Providers

A collection of [Keycloak](https://www.keycloak.org/) SPI providers.

- Java: `21`
- Default Keycloak (compile target): `26.7.1` (`keycloak.version` in the root POM)

### Supported Keycloak versions

Providers are developed against Keycloak **26.7.1**. CI recompiles and runs the unit suite against:

- `26.7.1`
- `26.6.4`
- `26.5.7`
- `26.4.7`

Versions outside this set (including other majors) are unsupported unless added to the CI matrix. Override locally with `-Dkeycloak.version=<version>`.

## Providers

| Provider | Description |
|----------|-------------|
| [last-login-timestamp](providers/last-login-timestamp/) | Event listener that records each user's most recent login as milliseconds since Unix epoch on a user attribute |

## Build

Requires a JDK 21 and Maven. From the repository root:

```bash
mvn clean package
```

Each provider builds to its own JAR under `providers/<name>/target/`.

## License

[MIT](LICENSE) © Dean Grant
