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
 */
public final class EmailOtpAuthenticator implements Authenticator {

  private static final Logger LOG = Logger.getLogger(EmailOtpAuthenticator.class);

  /** Auth-session note storing the SHA-256 hex digest of the emailed OTP. */
  public static final String AUTH_NOTE_OTP_HASH = "email-otp-hash";

  /** Auth-session note storing the OTP expiry as epoch seconds. */
  public static final String AUTH_NOTE_OTP_EXPIRY = "email-otp-expiry";

  /** HTML form field name for the submitted OTP code. */
  public static final String FORM_PARAM_OTP = "otp";

  /** Authenticator config key for OTP lifespan in seconds. */
  public static final String TTL_SECONDS = "otpTtlSeconds";

  public static final int DEFAULT_TTL_SECONDS = 5 * 60;
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
    List<ProviderConfigProperty> props = new ArrayList<>();
    props.add(ttl);
    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    sendOtpIfNeeded(context);
    context.challenge(otpForm(context, null));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if (formData.containsKey("resend")) {
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_HASH);
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_EXPIRY);
      sendOtpIfNeeded(context);
      context.challenge(otpForm(context, null));
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
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_HASH);
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_EXPIRY);
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
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_HASH);
      context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_EXPIRY);
      if (context.getAuthenticationSession().getAuthenticatedUser() != null) {
        context.getAuthenticationSession().getAuthenticatedUser().setEmailVerified(true);
      }
      context.success();
      return;
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
      LOG.debugf("Sent email OTP to %s", user.getEmail());
    } else {
      LOG.warnf("Failed to send email OTP to %s", user.getEmail());
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
    AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
    if (configModel == null || configModel.getConfig() == null) {
      return DEFAULT_TTL_SECONDS;
    }
    Map<String, String> config = configModel.getConfig();
    String value = config.get(TTL_SECONDS);
    if (value == null || value.isBlank()) {
      return DEFAULT_TTL_SECONDS;
    }
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return DEFAULT_TTL_SECONDS;
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
