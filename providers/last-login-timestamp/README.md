# Keycloak Last Login Timestamp Event Listener

Maven module (`me.deangrant.keycloak:last-login-timestamp`) that implements Keycloak’s **`eventsListener`** SPI (`EventListenerProvider` / `EventListenerProviderFactory`). On each successful user `LOGIN`, it writes the event time as **milliseconds since Unix epoch** to a single user attribute (default `lastLoginTimestamp`).

The attribute is an **advisory** operational signal—not a canonical audit trail. The write is deferred until after the login transaction commits, then run on a background executor so it never blocks or rolls back authentication.

| | |
|--|--|
| Provider ID | `last-login-timestamp` |
| Factory | `me.deangrant.keycloak.events.LastLoginTimestampListenerFactory` |
| Listener | `me.deangrant.keycloak.events.LastLoginTimestampListener` |
| Registration | `META-INF/services/org.keycloak.events.EventListenerProviderFactory` |
| Default attribute | `lastLoginTimestamp` (stringified epoch millis) |
| Compile target | Keycloak `26.7.1` (`keycloak.version` in the root POM) |
| CI-tested | `26.7.1`, `26.6.4`, `26.5.7`, `26.4.7` (see root [README](../../README.md)) |
| Java | `21` |

Keycloak SPI artifacts are Maven scope **`provided`**. Override the compile/test Keycloak version from the repo root with `-Dkeycloak.version=<version>`.

## Architecture

```text
LOGIN event (userId + realmId)
        │
        ▼
onEvent → DeferredLoginTransaction.enlistAfterCompletion
        │
        ├── login TX rollback → queue cleared (no write)
        └── login TX commit  → submit N tasks to 4-thread daemon pool
                                      │
                                      ▼
                         striped lock (256) by realmId/userId
                                      │
                                      ▼
                         fresh KeycloakSession + TX
                         read-compare-write attribute
                         (skip if stored ≥ event time)
```

### Event filtering

- Handles **`EventType.LOGIN` only**, and only when both `userId` and `realmId` are non-null.
- Ignores admin events (`onEvent(AdminEvent, …)` is a no-op).
- Does **not** update on `IMPERSONATE`, `CLIENT_LOGIN`, `REFRESH_TOKEN`, identity-provider login variants, or other non-`LOGIN` types.

### After-commit scheduling

- Each listener instance enlists a private `AbstractKeycloakTransaction` via `enlistAfterCompletion` on the request session’s transaction manager.
- Matching LOGIN events are queued on that deferred TX. On commit, each queued event is `executor.execute`’d; on rollback, the queue is cleared.
- The factory owns a fixed pool of **4 daemon** threads (`last-login-timestamp-*`), started in `init` and shut down in `close`. `RejectedExecutionException` is treated like any other update failure (WARN, no rethrow).

### Attribute write

- Under a **256-stripe** lock keyed by `Objects.hash(realmId, userId)`, the task opens a **fresh** session/transaction and uses public APIs only (`realms().getRealm`, `users().getUserById`, `getFirstAttribute` / `setSingleAttribute`).
- Replaces the attribute when the stored value is missing, blank, non-numeric, or **strictly older** than `event.getTime()`. Equal or newer values are left unchanged (**monotonic per node**).
- Missing realm or user aborts that write silently (no attribute change).
- All update-path exceptions are caught and logged at **`WARN`** on logger `org.keycloak.events` in Keycloak’s `key="value"` style. Allowlisted detail keys only: `auth_method`, `identity_provider`. **`sessionId` and `ipAddress` are omitted.** The `error=` field includes the exception simple name (for example `ReadOnlyException`). Secondary logging failures are also swallowed after a fallback WARN.

## Limitations

- Best-effort and monotonic **per Keycloak node**, not cluster-wide. Concurrent logins on different nodes can still race at the database; that is accepted for this advisory signal.
- Federated users in **READ_ONLY** (or similar) storage cannot receive attribute writes; failures are WARN-only and do not affect login. Changing federation edit mode (for example `UNSYNCED`) is outside this provider.
- The attribute may appear shortly **after** the login HTTP response returns.
- Do not rely on this attribute alone for audit or compliance—use Keycloak event logs or a dedicated audit store.
- The `eventsListener` SPI is internal and may change; this provider stays on that SPI contract and avoids private Keycloak helper utilities beyond it.
- Unexpected defects in the update path surface only as WARN (+ stack) on `org.keycloak.events`, not as thrown failures to the login flow.

## Build

From the repository root (JDK 21, Maven 3.9+):

```bash
mvn clean package -pl providers/last-login-timestamp -am
```

Artifact: `providers/last-login-timestamp/target/last-login-timestamp.jar`.

## Test

Unit tests only (JUnit 5 + Mockito)—helpers, factory/config/`ServiceLoader`, and mocked session/transaction event paths. No Testcontainers / Failsafe IT suite.

```bash
mvn -B test -pl providers/last-login-timestamp -am
# optional SPI version:
mvn -B test -pl providers/last-login-timestamp -am -Dkeycloak.version=26.4.7
```

## Install

```bash
cp providers/last-login-timestamp/target/last-login-timestamp.jar $KEYCLOAK_HOME/providers/
$KEYCLOAK_HOME/bin/kc.sh build
```

## Enable

Add `last-login-timestamp` under **Realm Settings → Events → Event listeners**.

After a successful interactive login, the value appears on the user under **Users → (user) → Attributes** as `lastLoginTimestamp` (or your configured name), milliseconds since Unix epoch.

## Configuration

Override the attribute name via SPI config:

```bash
--spi-events-listener--last-login-timestamp--attribute-name=myCustomAttribute
```

Validation:

- Pattern: `^[a-zA-Z][a-zA-Z0-9_]{0,63}$` (letter first; letters, digits, underscores; max 64 chars).
- Must not be a reserved user attribute: `id`, `username`, `email`, `firstName`, `lastName`, `emailVerified`, `enabled`, `locale`, `createdTimestamp`, `disabledReason`, `did`, `is_temporary_admin`.

Unset or blank → `lastLoginTimestamp`. Non-blank invalid → WARN on the factory logger and fallback to `lastLoginTimestamp`.

## License

[MIT](../../LICENSE) © Dean Grant
