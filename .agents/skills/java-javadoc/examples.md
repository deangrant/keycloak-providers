# JavaDoc examples

Snippets in the style of this repo’s Keycloak providers. Prefer the **Good**
form; **Bad** forms trip Spotless/Google formatting or Error Prone.

## Summary fragment (`MissingSummary`)

**Bad** — no summary, only a tag:

```java
/** @return the provider id */
public String getId() {
  return PROVIDER_ID;
}
```

**Good:**

```java
/** Returns the Keycloak authenticator provider id {@code magic-link}. */
public String getId() {
  return PROVIDER_ID;
}
```

## Empty block tags (`EmptyBlockTag`)

**Bad:**

```java
/**
 * Resolves or creates a user for the submitted email.
 *
 * @param session
 * @param email the address
 * @return
 */
```

**Good** — describe each tag, or omit useless tags:

```java
/**
 * Resolves or creates a user for the submitted email.
 *
 * @param session Keycloak session used for user lookup; never {@code null}
 * @param email address or username to resolve; may be blank
 * @return the existing or newly created user, or {@code null} if not found and
 *     create is disabled
 */
```

## Paragraph placement (Spotless / Google)

**Bad** — lone `<p>` line (fights Google Java Format conventions):

```java
/**
 * Factory for the last-login-timestamp event listener.
 *
 * <p>
 * Enable the listener on a realm by adding {@code last-login-timestamp}.
 */
```

**Good** — `<p>` immediately before the first word of the next paragraph:

```java
/**
 * Factory for the last-login-timestamp event listener.
 *
 * <p>Enable the listener on a realm by adding {@code last-login-timestamp}.
 */
```

## SPI / factory class

**Good** — summary plus how operators enable it; tags only when useful:

```java
/**
 * Registers the magic-link browser authenticator with Keycloak.
 *
 * <p>Appears in the admin console as {@code Magic Link}. Wire it into a
 * duplicated Browser flow in place of Username Password Form.
 *
 * @see AbstractMagicLinkAuthenticatorFactory
 */
public final class MagicLinkAuthenticatorFactory extends AbstractMagicLinkAuthenticatorFactory {
  /** Provider id registered with Keycloak: {@code magic-link}. */
  public static final String PROVIDER_ID = "magic-link";
}
```

## Wrong comment kind (`AlmostJavadoc` / `NotJavadoc`)

**Bad** — documentation markup inside a non-Javadoc comment:

```java
/*
 * Returns the OTP TTL in seconds.
 *
 * @param context flow context
 */
```

**Good:**

```java
/**
 * Returns the OTP lifespan in seconds from authenticator config.
 *
 * @param context authentication flow context; never {@code null}
 */
```

## Inline tags and escaping

**Bad** — malformed tag and bare `<`:

```java
/** Returns true if expiry < now. Uses @{code Time}. */
```

**Good:**

```java
/** Returns {@code true} when the stored OTP expiry is before the current time. */
```
