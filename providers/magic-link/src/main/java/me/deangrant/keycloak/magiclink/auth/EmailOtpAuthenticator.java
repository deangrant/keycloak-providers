package me.deangrant.keycloak.magiclink.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
 * <p>Wrong guesses are limited per emailed code ({@code otpMaxAttempts}, default 5). Resends are
 * limited by cooldown ({@code otpResendCooldownSeconds}, default 30) and a per-session send budget
 * ({@code otpMaxSends}, default 5). When realm brute-force detection is enabled, locked users are
 * refused before send or validate.
 */
public final class EmailOtpAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(EmailOtpAuthenticator.class);

  /** Auth-session note storing the HMAC-SHA256 hex digest of the emailed OTP. */
  public static final String AUTH_NOTE_OTP_HASH = "email-otp-hash";

  /** Auth-session note storing the per-code salt (hex) used with {@link #AUTH_NOTE_OTP_HASH}. */
  public static final String AUTH_NOTE_OTP_SALT = "email-otp-salt";

  /** Auth-session note storing the OTP expiry as epoch seconds. */
  public static final String AUTH_NOTE_OTP_EXPIRY = "email-otp-expiry";

  /** Auth-session note counting wrong OTP submissions for the current code. */
  public static final String AUTH_NOTE_OTP_ATTEMPTS = "email-otp-attempts";

  /** Auth-session note storing epoch seconds of the last successful OTP email. */
  public static final String AUTH_NOTE_OTP_LAST_SENT = "email-otp-last-sent";

  /** Auth-session note counting successful OTP emails in this authentication session. */
  public static final String AUTH_NOTE_OTP_SEND_COUNT = "email-otp-send-count";

  /** HTML form field name for the submitted OTP code. */
  public static final String FORM_PARAM_OTP = "otp";

  /** Theme message key when resend is blocked by cooldown. */
  public static final String MSG_RESEND_COOLDOWN = "otpFormResendCooldown";

  /** Theme message key when resend is blocked by the per-session send budget. */
  public static final String MSG_RESEND_LIMIT = "otpFormResendLimit";

  /** Authenticator config key for OTP lifespan in seconds. */
  public static final String TTL_SECONDS = "otpTtlSeconds";

  /** Authenticator config key for max wrong guesses per emailed code. */
  public static final String MAX_ATTEMPTS = "otpMaxAttempts";

  /** Authenticator config key for minimum seconds between successful OTP emails. */
  public static final String RESEND_COOLDOWN_SECONDS = "otpResendCooldownSeconds";

  /** Authenticator config key for max successful OTP emails per authentication session. */
  public static final String MAX_SENDS = "otpMaxSends";

  public static final int DEFAULT_TTL_SECONDS = 5 * 60;
  public static final int DEFAULT_MAX_ATTEMPTS = 5;
  public static final int DEFAULT_RESEND_COOLDOWN_SECONDS = 30;
  public static final int DEFAULT_MAX_SENDS = 5;
  public static final int OTP_LENGTH = 6;
  public static final int OTP_SALT_BYTES = 16;

  private static final String HMAC_SHA256 = "HmacSHA256";

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

    ProviderConfigProperty cooldown = new ProviderConfigProperty();
    cooldown.setName(RESEND_COOLDOWN_SECONDS);
    cooldown.setLabel("OTP resend cooldown (seconds)");
    cooldown.setHelpText(
        "Minimum seconds between successful OTP emails. Default is 30. Resend during the cooldown"
            + " keeps the current code and shows an error.");
    cooldown.setType(ProviderConfigProperty.STRING_TYPE);
    cooldown.setDefaultValue(String.valueOf(DEFAULT_RESEND_COOLDOWN_SECONDS));

    ProviderConfigProperty maxSends = new ProviderConfigProperty();
    maxSends.setName(MAX_SENDS);
    maxSends.setLabel("OTP max sends");
    maxSends.setHelpText(
        "Maximum successful OTP emails allowed in one authentication session (including the"
            + " first). Default is 5.");
    maxSends.setType(ProviderConfigProperty.STRING_TYPE);
    maxSends.setDefaultValue(String.valueOf(DEFAULT_MAX_SENDS));

    List<ProviderConfigProperty> props = new ArrayList<>();
    props.add(ttl);
    props.add(maxAttempts);
    props.add(cooldown);
    props.add(maxSends);
    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (challengeIfBruteForceLocked(context)) {
      return;
    }
    if (!sendOtpIfNeeded(context)) {
      challengeEmailSendFailed(context);
      return;
    }
    context.challenge(otpForm(context, null));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    if (challengeIfBruteForceLocked(context)) {
      return;
    }

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if (formData.containsKey("resend")) {
      handleResend(context);
      return;
    }

    int maxAttempts = maxAttempts(context);
    int attempts = readIntNote(context, AUTH_NOTE_OTP_ATTEMPTS);
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
    String saltHex = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_SALT);
    String expiryRaw = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_EXPIRY);

    if (expectedHash == null || saltHex == null || expiryRaw == null) {
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

    if (otpMatches(code, saltHex, expectedHash)) {
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

  private void handleResend(AuthenticationFlowContext context) {
    int sendCount = readIntNote(context, AUTH_NOTE_OTP_SEND_COUNT);
    if (sendCount >= maxSends(context)) {
      context.challenge(otpForm(context, new FormMessage(FORM_PARAM_OTP, MSG_RESEND_LIMIT)));
      return;
    }

    int lastSent = readIntNote(context, AUTH_NOTE_OTP_LAST_SENT);
    if (lastSent > 0 && Time.currentTime() < lastSent + resendCooldownSeconds(context)) {
      context.challenge(otpForm(context, new FormMessage(FORM_PARAM_OTP, MSG_RESEND_COOLDOWN)));
      return;
    }

    clearOtpNotes(context);
    if (!sendOtpIfNeeded(context)) {
      challengeEmailSendFailed(context);
      return;
    }
    context.challenge(otpForm(context, null));
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

  private void challengeEmailSendFailed(AuthenticationFlowContext context) {
    context
        .getEvent()
        .user(context.getUser())
        .event(EventType.LOGIN_ERROR)
        .error(Errors.EMAIL_SEND_FAILED);
    context.failureChallenge(
        AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR,
        otpForm(context, new FormMessage(Messages.EMAIL_SENT_ERROR)));
  }

  /**
   * Sends an OTP when none is pending for this authentication session.
   *
   * @return {@code true} when an OTP is already pending or a new email was sent; {@code false} when
   *     send failed (or no user)
   */
  private boolean sendOtpIfNeeded(AuthenticationFlowContext context) {
    if (context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_HASH) != null) {
      return true;
    }

    UserModel user = context.getUser();
    if (user == null) {
      LOG.warn("Email OTP authenticator requires an identified user");
      return false;
    }

    String code = SecretGenerator.getInstance().randomString(OTP_LENGTH, SecretGenerator.DIGITS);
    boolean sent = MagicLinkSupport.sendOtpEmail(context.getSession(), user, code);
    if (sent) {
      byte[] salt = generateSalt();
      context.getAuthenticationSession().setAuthNote(AUTH_NOTE_OTP_SALT, toHex(salt));
      context.getAuthenticationSession().setAuthNote(AUTH_NOTE_OTP_HASH, hash(code, salt));
      context
          .getAuthenticationSession()
          .setAuthNote(
              AUTH_NOTE_OTP_EXPIRY, String.valueOf(Time.currentTime() + ttlSeconds(context)));
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
      int nextSendCount = readIntNote(context, AUTH_NOTE_OTP_SEND_COUNT) + 1;
      context
          .getAuthenticationSession()
          .setAuthNote(AUTH_NOTE_OTP_SEND_COUNT, String.valueOf(nextSendCount));
      context
          .getAuthenticationSession()
          .setAuthNote(AUTH_NOTE_OTP_LAST_SENT, String.valueOf(Time.currentTime()));
      LOG.debugf("Sent email OTP to %s", user.getEmail());
      return true;
    }
    LOG.warnf("Failed to send email OTP to %s", user.getEmail());
    return false;
  }

  private void clearOtpNotes(AuthenticationFlowContext context) {
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_HASH);
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_SALT);
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_EXPIRY);
    context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_ATTEMPTS);
  }

  private int readIntNote(AuthenticationFlowContext context, String note) {
    String raw = context.getAuthenticationSession().getAuthNote(note);
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

  private int resendCooldownSeconds(AuthenticationFlowContext context) {
    return intConfig(context, RESEND_COOLDOWN_SECONDS, DEFAULT_RESEND_COOLDOWN_SECONDS);
  }

  private int maxSends(AuthenticationFlowContext context) {
    return intConfig(context, MAX_SENDS, DEFAULT_MAX_SENDS);
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

  /** Generates a fresh per-code salt. */
  static byte[] generateSalt() {
    return SecretGenerator.getInstance().randomBytes(OTP_SALT_BYTES);
  }

  /**
   * Returns the HMAC-SHA256 hex digest of {@code code} keyed by {@code salt}.
   *
   * @param code plaintext OTP; never {@code null}
   * @param salt per-code salt; never {@code null}
   * @return lowercase hex MAC
   */
  static String hash(String code, byte[] salt) {
    try {
      Mac mac = Mac.getInstance(HMAC_SHA256);
      mac.init(new SecretKeySpec(salt, HMAC_SHA256));
      return toHex(mac.doFinal(code.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException("HMAC-SHA256 unavailable", e);
    }
  }

  /**
   * Returns whether {@code code} matches the stored salt and HMAC hex digest.
   *
   * @param code submitted OTP; may be {@code null}
   * @param saltHex stored salt hex; may be {@code null}
   * @param hashHex stored HMAC hex; may be {@code null}
   * @return {@code true} only when all inputs are present and the MAC matches
   */
  static boolean otpMatches(String code, String saltHex, String hashHex) {
    if (code == null || saltHex == null || hashHex == null) {
      return false;
    }
    try {
      byte[] salt = fromHex(saltHex);
      String actual = hash(code, salt);
      return MessageDigest.isEqual(
          actual.getBytes(StandardCharsets.UTF_8), hashHex.getBytes(StandardCharsets.UTF_8));
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  static String toHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  static byte[] fromHex(String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("odd hex length");
    }
    byte[] out = new byte[hex.length() / 2];
    for (int i = 0; i < out.length; i++) {
      int index = i * 2;
      out[i] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
    }
    return out;
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
