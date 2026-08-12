# Keycloak Last Login Timestamp Event Listener

A [Keycloak](https://www.keycloak.org/) event listener that records each user's most recent login as a Unix epoch timestamp (milliseconds) in a user attribute.

## Overview

The provider hooks into Keycloak's event system and, on every successful `LOGIN` event, writes the login time to a user attribute (default: `lastLoginTimestamp`). The write happens in a separate transaction after the login commits, so it never blocks or rolls back authentication.

- Provider ID: `last-login-timestamp`
- Default attribute: `lastLoginTimestamp`
- Keycloak: `26.6.4`
- Java: `21`

## How it works

- Listens for `EventType.LOGIN` and queues each event on a deferred `AbstractKeycloakTransaction` enlisted with `enlistAfterCompletion`.
- After the login transaction commits, one fresh session/transaction under a striped lock keyed by realm/user performs read-compare-write via public Keycloak session APIs. The write is skipped when the stored timestamp is already equal to or newer than the event time (monotonic per node). Same-user updates share a stripe; a fixed 256-stripe table avoids unbounded per-user lock maps.
- Failures are caught and logged at `WARN` on the `org.keycloak.events` logger using Keycloak's native `key="value"` format. Only non-sensitive detail keys are logged; `sessionId` and `ipAddress` are omitted.

### Limitations

- Updates are best-effort and monotonic **per Keycloak node**, not cluster-wide. In a multi-node deployment, concurrent logins routed to different nodes may still race at the database layer.
- Do not rely on this attribute alone for audit or compliance. Use Keycloak event logs or a dedicated audit store if canonical login history is required.
- The Keycloak `eventsListener` SPI is internal and may change; this provider uses that SPI contract but avoids private Keycloak helper utilities beyond it.

## Build

From the repository root (requires JDK 21 and Maven):

```bash
mvn clean package -pl providers/last-login-timestamp -am
```

Or build all providers:

```bash
mvn clean package
```

This produces `providers/last-login-timestamp/target/last-login-timestamp.jar`.

## Install

Copy the built JAR into your Keycloak `providers/` directory and rebuild:

```bash
cp providers/last-login-timestamp/target/last-login-timestamp.jar $KEYCLOAK_HOME/providers/
$KEYCLOAK_HOME/bin/kc.sh build
```

## Enable

Enable the listener on a realm via **Realm Settings > Events > Event listeners** by adding `last-login-timestamp` to the list of event listeners.

After a user logs in, the timestamp appears on the user under **Users > (user) > Attributes** as `lastLoginTimestamp` (epoch milliseconds).

## Configuration

The user attribute name can be overridden through the SPI configuration:

```bash
--spi-events-listener--last-login-timestamp--attribute-name=myCustomAttribute
```

The name must match `^[a-zA-Z][a-zA-Z0-9_]{0,63}$` (start with a letter; letters, digits, and underscores only; max 64 characters) and must not be a reserved user attribute: `id`, `username`, `email`, `firstName`, `lastName`, `emailVerified`, `enabled`, `locale`, `createdTimestamp`, `disabledReason`, `did`, or `is_temporary_admin`. This prevents a misconfiguration from overwriting unrelated user data.

If unset or blank, the attribute name defaults to `lastLoginTimestamp`. If a non-blank value fails validation, it is rejected with a `WARN` log and `lastLoginTimestamp` is used instead.

## License

[MIT](../../LICENSE) © Dean Grant
