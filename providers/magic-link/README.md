# Magic Link

Browser-flow authenticators for passwordless email sign-in: **Magic Link**, **Magic Link Continuation**, and **Email OTP**.

Provider JAR: `providers/magic-link/target/magic-link.jar`  
Provider IDs: `magic-link`, `magic-link-continuation`, `email-otp`

## Overview

| Authenticator | Behavior |
|---------------|----------|
| Magic Link | Collects email, optionally creates the user, emails a signed action-token link. Opening the link completes login on that browser (cross-device). |
| Magic Link Continuation | Same email step, but the **original** device polls until the link is opened elsewhere and confirms the session. |
| Email OTP | After the user is identified (e.g. Username Form), emails a 6-digit code and validates it. |

Emails use FreeMarker templates shipped in `theme-resources` and can be overridden in a custom email/login theme.

## Install

1. Build: `mvn clean package -pl providers/magic-link -am`
2. Copy `providers/magic-link/target/magic-link.jar` into Keycloak’s `providers/` directory.
3. Rebuild/restart Keycloak (`kc.sh build` if required by your distribution).
4. Configure realm SMTP under **Realm settings → Email**.

## Browser flow setup

### Magic Link

1. Duplicate the Browser flow.
2. Replace **Username Password Form** with **Magic Link** (REQUIRED), or add it as an ALTERNATIVE alongside password.
3. Bind the flow as the realm Browser flow.
4. Optional authenticator config:
   - **Create user if missing**
   - **Update profile on create** / **Update password on create**
   - **Token lifespan (seconds)** (default `900`)

### Magic Link Continuation

1. Use **Magic Link Continuation** instead of Magic Link in the forms sub-flow.
2. Configure **Expiration (minutes)** (default `10`) and optional create-user.
3. Keep the waiting tab open; it posts back every 5 seconds until the emailed link confirms the session.

### Email OTP

Recommended after **Username Form**:

```
Browser forms
├── Username Form          [REQUIRED]
└── Email OTP              [REQUIRED]
```

Optional config: **OTP lifespan (seconds)** (default `300`), **OTP max attempts** (default `5`).

## Email and login templates

Shipped under `theme-resources/`:

| Template | Purpose |
|----------|---------|
| `templates/html|text/magic-link-email.ftl` | Magic link message body |
| `templates/html|text/magic-link-continuation-email.ftl` | Continuation message body |
| `templates/html|text/email-otp.ftl` | OTP message body |
| `templates/view-email.ftl` | “Check your email” waiting page |
| `templates/view-email-continuation.ftl` | Continuation polling page |
| `templates/otp-form.ftl` | OTP entry form |
| `templates/email-confirmation.ftl` | Click-device success for continuation |
| `templates/email-confirmation-error.ftl` | Click-device error for continuation |
| `messages/messages_en.properties` | Subject keys and UI strings |

Override by placing same-named files in a custom theme (email theme for `html/`/`text/` templates and subject keys; login theme for form templates).

Subject message keys: `magicLinkSubject`, `magicLinkContinuationSubject`, `otpSubject`.

## Library extension (SPI)

Depend on this module from another Keycloak extension:

```xml
<dependency>
  <groupId>me.deangrant.keycloak</groupId>
  <artifactId>magic-link</artifactId>
  <version>1.0.0</version>
</dependency>
```

1. Implement `MagicLinkCustomizationProvider` (`canAuthenticate`, `sendMagicLinkEmail`).
2. Implement `MagicLinkCustomizationProviderFactory`.
3. Subclass `AbstractMagicLinkAuthenticatorFactory`, pass your factory, and use a unique `PROVIDER_ID`.
4. Register your factory in `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`.

`MagicLinkAuthenticator` and the action-token handlers are `final`. Continuation and Email OTP are self-contained and do not use the customization SPI.

## Limitations

- Requires working realm SMTP; failed sends are logged and do not authenticate the user.
- When SMTP fails for a **known** user, Magic Link / Continuation / Email OTP show an email-send error so the user can retry; the waiting or continuation session is not started. Unknown emails still get the generic waiting page (anti-enumeration).
- Magic Link / Continuation action tokens are single-use.
- Magic Link and Continuation show the same waiting page for unknown emails (no mail sent) to avoid account enumeration.
- With `forceCreate`, a user may be created before the email is sent (action tokens need a user id); if the send fails (or customization denies auth), that newly created user is removed and `REGISTER` is emitted only after a successful send.
- Continuation confirmation depends on the original authentication session still being alive in the cluster.
- Email OTP stores a SHA-256 hash of the code in the authentication session (not the plaintext code).
- Email OTP invalidates the current code after too many wrong guesses (`otpMaxAttempts`, default 5); the user must resend for a new code and attempt budget.
- Enable realm **Brute force detection** for account-level lockout across sessions/IPs; Email OTP respects those lockouts when enabled.
- Compile/runtime APIs come from Keycloak (`keycloak-services` is `provided`); do not shade Keycloak into the JAR.
- Supported Keycloak versions match the repository matrix (see root README).

## Configuration reference

| Provider ID | Config keys |
|-------------|-------------|
| `magic-link` | `forceCreate`, `updateProfile`, `updatePassword`, `tokenLifespanSeconds` |
| `magic-link-continuation` | `forceCreate`, `timeoutMinutes` |
| `email-otp` | `otpTtlSeconds`, `otpMaxAttempts` |
