# Keycloak Providers

A collection of [Keycloak](https://www.keycloak.org/) SPI providers.

- Keycloak: `26.6.4`
- Java: `21`

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
