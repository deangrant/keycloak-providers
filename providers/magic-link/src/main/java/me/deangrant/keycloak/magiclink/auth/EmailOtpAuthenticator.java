package me.deangrant.keycloak.magiclink.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.util.AuthenticatorUtils;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;

/**
 * Emails a 6-digit OTP and validates it. Intended after a Username Form (or any step that
 * identifies the user).
 *
 * <p>Wrong guesses are limited per emailed code ({@code otpMaxAttempts}, default 5). When realm
 * brute-force detection is enabled, locked users are refused before send or validate.
 */
public final class EmailOtpAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(EmailOtpAuthenticator.class);

  /** Auth-session note storing the SHA-256 hex digest of the emailed OTP. */
  public static final String AUTH_NOTE_OTP_HASH = "email-otp-hash";

  /** Auth-session note storing the OTP expiry as epoch seconds. */
  public static final String AUTH_NOTE_OTP_EXPIRY = "email-otp-expiry";

  /** Auth-session note counting wrong OTP submissions for the current code. */
  public static final String AUTH_NOTE_OTP_ATTEMPTS = "email-otp-attempts";

  /** HTML form field name for the submitted OTP code. */
  public static final String FORM_PARAM_OTP = "otp";

  /** Authenticator config key for OTP lifespan in seconds. */
  public static final String TTL_SECONDS = "otpTtlSeconds";

  /** Authenticator config key for max wrong guesses per emailed code. */
  public static final String MAX_ATTEMPTS = "otpMaxAttempts";

  public static final int DEFAULT_TTL_SECONDS = 5 * 60;
  public static final int DEFAULT_MAX_ATTEMPTS = 5;
  public static final int OTP_LENGTH = 6;

  /** Admin-UI config properties for this authenticator. */
  public static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    ProviderConfigProperty ttl = new ProviderConfigProperty();
    ttl.setName(TTL_SECONDS);
    ttl.setLabel("OTP lifespan (seconds)");
    ttl.setHelpText("How long the emailed OTP remains valid. Default is 300 (5 minutes).");
    ttl.setType(ProviderConfigProperty.STRING_TYPE);
    ttl.setDefaultValue(String.valueOf(DEFAULT_TTL_SECONDS));

    ProviderConfigProperty maxAttempts = new ProviderConfigProperty();
    maxAttempts.setName(MAX_ATTEMPTS);
    maxAttempts.setLabel("OTP max attempts");
    maxAttempts.setHelpText(
        "Maximum wrong guesses allowed for one emailed code before it is invalidated."
            + " Default is 5. The user must resend for a new code.");
    maxAttempts.setType(ProviderConfigProperty.STRING_TYPE);
    maxAttempts.setDefaultValue(String.valueOf(DEFAULT_MAX_ATTEMPTS));

    List<ProviderConfigProperty> props = new ArrayList<>();
    props.add(ttl);
    props.add(maxAttempts);
    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (challengeIfBruteForceLocked(context)) {
      return;
    }
    sendOtpIfNeeded(context);
    context.challenge(otpForm(context, null));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    if (challengeIfBruteForceLocked(context)) {
      return;
    }

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if (formData.containsKey("resend")) {
      clearOtpNotes(context);
      sendOtpIfNeeded(context);
      context.challenge(otpForm(context, null));
      return;
    }

    int maxAttempts = maxAttempts(context);
    int attempts = readAttempts(context);
    if (attempts >= maxAttempts) {
      clearOtpNotes(context);
      context
          .getEvent()
          .user(context.getUser())
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_CODE);
      context.failureChallenge(
          AuthenticationFlowError.INVALID_CREDENTIALS,
          otpForm(context, new FormMessage(Messages.INVALID_ACCESS_CODE)));
      return;
    }

    String code = MagicLinkSupport.trimToNull(formData.getFirst(FORM_PARAM_OTP));
    String expectedHash = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_HASH);
    String expiryRaw = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_EXPIRY);

    if (expectedHash == null || expiryRaw == null) {
      context
          .getEvent()
          .user(context.getUser())
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_CODE);
      context.failureChallenge(
          AuthenticationFlowError.INVALID_CREDENTIALS,
          otpForm(context, new FormMessage(Messages.INVALID_ACCESS_CODE)));
      return;
    }

    long expiry;
    try {
      expiry = Long.parseLong(expiryRaw);
    } catch (NumberFormatException e) {
      expiry = 0L;
    }

    if (Time.currentTime() > expiry) {
      clearOtpNotes(context);
      context
          .getEvent()
          .user(context.getUser())
          .event(EventType.LOGIN_ERROR)
          .error(Errors.EXPIRED_CODE);
      context.failureChallenge(
          AuthenticationFlowError.EXPIRED_CODE,
          otpForm(context, new FormMessage(Messages.EXPIRED_ACTION_TOKEN_NO_SESSION)));
      return;
    }

    if (code != null
        && MessageDigest.isEqual(
            hash(code).getBytes(StandardCharsets.UTF_8),
            expectedHash.getBytes(StandardCharsets.UTF_8))) {
      clearOtpNotes(context);
      if (context.getAuthenticationSession().getAuthenticatedUser() != null) {
        context.getAuthenticationSession().getAuthenticatedUser().setEmailVerified(true);
      }
      context.success();
      return;
    }

    int nextAttempts = attempts + 1;
    if (nextAttempts >= maxAttempts) {
      clearOtpNotes(context);
    } else {
      context
          .getAuthenticationSession()
          .setAuthNote(AUTH_NOTE_OTP_ATTEMPTS, String.valueOf(nextAttempts));
    }

    context
        .getEvent()
        .user(context.getUser())
        .event(EventType.LOGIN_ERROR)
        .error(Errors.INVALID_CODE);
    context.failureChallenge(
        AuthenticationFlowError.INVALID_CREDENTIALS,
        otpForm(context, new FormMessage(Messages.INVALID_ACCESS_CODE)));
  }

  /**
   * Returns {@code true} when the user is locked by realm brute-force detection and a lockout
   * challenge has already been set.
   */
  private boolean challengeIfBruteForceLocked(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (user == null) {
      return false;
    }
    String bruteForceError = AuthenticatorUtils.getDisabledByBruteForceEventError(context, user);
    if (bruteForceError == null) {
      return false;
    }
    context.getEvent().user(user).error(bruteForceError);
    context.forceChallenge(
        otpForm(context, new FormMessage(disabledByBruteForceMessage(bruteForceError))));
    return true;
  }

  private static String disabledByBruteForceMessage(String error) {
    if (Errors.USER_TEMPORARILY_DISABLED.equals(error)) {
      return Messages.ACCOUNT_TEMPORARILY_DISABLED;
    }
    return Messages.ACCOUNT_PERMANENTLY_DISABLED;
  }

  private void sendOtpIfNeeded(AuthenticationFlowContext context) {
    if (context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_HASH) != null) {
      return;
    }

    UserModel user = context.getUser();
    if (user == null) {
      LOG.warn("Email OTP authenticator requires an identified user");
      return;
    }

    String code = SecretGenerator.getInstance().randomString(OTP_LENGTH, SecretGenerator.DIGITS);
    boolean sent = MagicLinkSupport.sendOtpEmail(context.getSession(), user, code);
    if (sent) {
      context.getAuthenticationSession().setAuthNote(AUTH_NOTE_OTP_HASH, hash(code));
      context
          .getAuthenticationSession()
          .setAuthNote(
              AUTH_NOTE_OTP_EXPIRY, String.valueOf(Time.currentTime() + ttlSeconds(context)));
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
      LOG.debugf("Sent email OTP to %s", user.getEmail());
    } else {
      LOG.warnf("Failed to send email OTP to %s", user.getEmail());
    }
  }

  private void clearOtpNotes(AuthenticationFlowContext context) {
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_HASH);
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_EXPIRY);
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
  }

  private int readAttempts(AuthenticationFlowContext context) {
    String raw = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
    if (raw == null || raw.isBlank()) {
      return 0;
    }
    try {
      return Integer.parseInt(raw.trim());
    } catch (NumberFormatException e) {
      return 0;
    }
  }

  private Response otpForm(AuthenticationFlowContext context, FormMessage error) {
    LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
    if (error != null) {
      form.setErrors(List.of(error));
    }
    return form.createForm("otp-form.ftl");
  }

  private int ttlSeconds(AuthenticationFlowContext context) {
    return intConfig(context, TTL_SECONDS, DEFAULT_TTL_SECONDS);
  }

  private int maxAttempts(AuthenticationFlowContext context) {
    return intConfig(context, MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS);
  }

  private static int intConfig(AuthenticationFlowContext context, String key, int defaultValue) {
    AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
    if (configModel == null || configModel.getConfig() == null) {
      return defaultValue;
    }
    Map<String, String> config = configModel.getConfig();
    String value = config.get(key);
    if (value == null || value.isBlank()) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      return parsed > 0 ? parsed : defaultValue;
    } catch (NumberFormatException e) {
      return defaultValue;
    }
  }

  static String hash(String code) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hashed = digest.digest(code.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(hashed.length * 2);
      for (byte b : hashed) {
        sb.append(String.format("%02x", b));
      }
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return user != null && MagicLinkSupport.trimToNull(user.getEmail()) != null;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

  @Override
  public void close() {}
}
