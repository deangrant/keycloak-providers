package me.deangrant.keycloak.magiclink.auth.continuation;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;

/**
 * Magic-link continuation: the original device polls until the emailed link confirms the session.
 */
public final class MagicLinkContinuationAuthenticator extends UsernamePasswordForm {

  private static final Logger LOG = Logger.getLogger(MagicLinkContinuationAuthenticator.class);

  /** Authenticator config key for waiting-session timeout in minutes. */
  public static final String TIMEOUT_MINUTES = "timeoutMinutes";

  public static final int DEFAULT_TIMEOUT_MINUTES = 10;

  /** Admin-UI config properties for this authenticator. */
  public static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

  static {
    ProviderConfigProperty timeout = new ProviderConfigProperty();
    timeout.setName(TIMEOUT_MINUTES);
    timeout.setLabel("Expiration (minutes)");
    timeout.setHelpText(
        "How long the original device waits for the magic link to be confirmed. Default is 10.");
    timeout.setType(ProviderConfigProperty.STRING_TYPE);
    timeout.setDefaultValue(String.valueOf(DEFAULT_TIMEOUT_MINUTES));

    ProviderConfigProperty forceCreate = new ProviderConfigProperty();
    forceCreate.setName(me.deangrant.keycloak.magiclink.auth.MagicLinkConfig.FORCE_CREATE);
    forceCreate.setLabel("Create user if missing");
    forceCreate.setHelpText(
        "When enabled, creates a user with the submitted email as username/email if none exists.");
    forceCreate.setType(ProviderConfigProperty.BOOLEAN_TYPE);
    forceCreate.setDefaultValue("false");

    List<ProviderConfigProperty> props = new ArrayList<>();
    props.add(forceCreate);
    props.add(timeout);
    CONFIG_PROPERTIES = Collections.unmodifiableList(props);
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (sessionExpired(context)) {
      AuthenticationSessionManager manager = new AuthenticationSessionManager(context.getSession());
      manager.removeTabIdInAuthenticationSession(
          context.getRealm(), context.getAuthenticationSession());
      context.getEvent().error(Errors.SESSION_EXPIRED);
      Response challengeResponse =
          challenge(context, Messages.EXPIRED_ACTION_TOKEN_NO_SESSION, FIELD_USERNAME);
      context.failureChallenge(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challengeResponse);
      return;
    }

    if (isConfirmed(context)) {
      completeSuccess(context);
      return;
    }

    String attemptedUsername = MagicLinkSupport.getAttemptedUsername(context);
    if (attemptedUsername == null) {
      super.authenticate(context);
      return;
    }

    String initiated =
        context.getAuthenticationSession().getAuthNote(ContinuationNotes.SESSION_INITIATED);
    if (initiated == null || initiated.isBlank()) {
      action(context);
      return;
    }

    context.challenge(context.form().createForm("view-email-continuation.ftl"));
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    if (sessionExpired(context)) {
      authenticate(context);
      return;
    }

    if (isConfirmed(context)) {
      completeSuccess(context);
      return;
    }

    // Polling posts back to loginAction; keep waiting if already initiated.
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if ("true".equals(formData.getFirst("poll"))
        && context.getAuthenticationSession().getAuthNote(ContinuationNotes.SESSION_INITIATED)
            != null) {
      context.challenge(context.form().createForm("view-email-continuation.ftl"));
      return;
    }

    String email =
        MagicLinkSupport.trimToNull(formData.getFirst(AuthenticationManager.FORM_USERNAME));
    if (email == null) {
      email = MagicLinkSupport.getAttemptedUsername(context);
    }
    if (email == null) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }

    boolean forceCreate =
        Boolean.parseBoolean(
            configValue(
                context,
                me.deangrant.keycloak.magiclink.auth.MagicLinkConfig.FORCE_CREATE,
                "false"));

    MagicLinkSupport.GetOrCreateResult created =
        MagicLinkSupport.getOrCreate(
            context.getSession(), context.getRealm(), email, forceCreate, false, false);
    UserModel user = created.user();

    if (user == null
        || MagicLinkSupport.trimToNull(user.getEmail()) == null
        || !MagicLinkSupport.isValidEmail(user.getEmail())) {
      context
          .getEvent()
          .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_EMAIL);
      // Avoid account enumeration: same waiting page and session notes as a successful send.
      beginWaitingSession(context, email);
      context.forceChallenge(context.form().createForm("view-email-continuation.ftl"));
      return;
    }

    if (!enabledUser(context, user)) {
      if (created.created()) {
        MagicLinkSupport.removeUser(context.getSession(), context.getRealm(), user);
      }
      // Avoid enumeration / stall: same waiting page as unknown email (no mail).
      beginWaitingSession(context, email);
      context.forceChallenge(context.form().createForm("view-email-continuation.ftl"));
      return;
    }

    int timeoutMinutes = getTimeoutMinutes(context);
    int validitySeconds = 60 * timeoutMinutes;
    String clientId = context.getSession().getContext().getClient().getClientId();
    MagicLinkContinuationActionToken token =
        MagicLinkSupport.createContinuationToken(
            user, clientId, validitySeconds, context.getAuthenticationSession());
    String link =
        MagicLinkSupport.linkFromActionToken(context.getSession(), context.getRealm(), token);
    boolean sent = MagicLinkSupport.sendContinuationEmail(context.getSession(), user, link);
    LOG.debugf("Continuation magic link email to %s sent=%s", user.getEmail(), sent);

    MagicLinkSupport.finalizeForceCreatedUser(
        context.getSession(),
        context.getRealm(),
        created,
        sent,
        context.newEvent(),
        MagicLinkSupport.REGISTER_METHOD_MAGIC_LINK);

    if (!sent) {
      context
          .getAuthenticationSession()
          .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      context.getEvent().user(user).event(EventType.LOGIN_ERROR).error(Errors.EMAIL_SEND_FAILED);
      Response challengeResponse = challenge(context, Messages.EMAIL_SENT_ERROR, FIELD_USERNAME);
      context.failureChallenge(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challengeResponse);
      return;
    }

    MagicLinkSupport.rememberLatestActionToken(context.getSession(), token, validitySeconds);
    beginWaitingSession(context, email);
    context.challenge(context.form().createForm("view-email-continuation.ftl"));
  }

  /**
   * Marks the authentication session as waiting for continuation confirmation so polls use the same
   * path for known and unknown emails.
   */
  private void beginWaitingSession(AuthenticationFlowContext context, String email) {
    int timeoutMinutes = getTimeoutMinutes(context);
    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    context.getAuthenticationSession().setAuthNote(ContinuationNotes.SESSION_INITIATED, "true");
    context
        .getAuthenticationSession()
        .setAuthNote(
            ContinuationNotes.SESSION_EXPIRATION,
            ZonedDateTime.now(ZoneOffset.UTC)
                .plusMinutes(timeoutMinutes)
                .plusSeconds(2)
                .toString());
  }

  private void completeSuccess(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    if (user == null) {
      user = context.getAuthenticationSession().getAuthenticatedUser();
    }
    if (user == null) {
      String attemptedUsername = MagicLinkSupport.getAttemptedUsername(context);
      if (attemptedUsername != null) {
        user =
            KeycloakModelUtils.findUserByNameOrEmail(
                context.getSession(), context.getRealm(), attemptedUsername);
      }
    }
    if (user == null) {
      LOG.warn("Continuation confirmed but user could not be resolved");
      String attemptedUsername = MagicLinkSupport.getAttemptedUsername(context);
      EventBuilder event = context.getEvent().event(EventType.LOGIN_ERROR);
      if (attemptedUsername != null) {
        event.detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, attemptedUsername);
      }
      event.error(Errors.USER_NOT_FOUND);
      Response challengeResponse =
          challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      return;
    }
    context.setUser(user);
    context.getAuthenticationSession().setAuthenticatedUser(user);
    context.success();
  }

  private boolean isConfirmed(AuthenticationFlowContext context) {
    String confirmed =
        context.getAuthenticationSession().getAuthNote(ContinuationNotes.SESSION_CONFIRMED);
    return confirmed != null && !confirmed.isBlank();
  }

  private boolean sessionExpired(AuthenticationFlowContext context) {
    return isExpirationElapsed(
        context.getAuthenticationSession().getAuthNote(ContinuationNotes.SESSION_EXPIRATION));
  }

  /** Package-visible for unit tests. */
  static boolean isExpirationElapsed(String expiration) {
    if (expiration == null || expiration.isBlank()) {
      return false;
    }
    return ZonedDateTime.parse(expiration).isBefore(ZonedDateTime.now(ZoneOffset.UTC));
  }

  private int getTimeoutMinutes(AuthenticationFlowContext context) {
    String value = configValue(context, TIMEOUT_MINUTES, String.valueOf(DEFAULT_TIMEOUT_MINUTES));
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException e) {
      return DEFAULT_TIMEOUT_MINUTES;
    }
  }

  private String configValue(AuthenticationFlowContext context, String key, String defaultValue) {
    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig == null || authenticatorConfig.getConfig() == null) {
      return defaultValue;
    }
    Map<String, String> config = authenticatorConfig.getConfig();
    String value = config.get(key);
    return value == null || value.isBlank() ? defaultValue : value;
  }

  @Override
  protected boolean validateForm(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    return validateUser(context, formData);
  }

  @Override
  protected Response challenge(
      AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
    LoginFormsProvider forms = context.form();
    if (!formData.isEmpty()) {
      forms.setFormData(formData);
    }
    return forms.createLoginUsername();
  }

  @Override
  protected Response createLoginForm(LoginFormsProvider form) {
    return form.createLoginUsername();
  }

  @Override
  protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
    return context.getRealm().isLoginWithEmailAllowed()
        ? Messages.INVALID_USERNAME_OR_EMAIL
        : Messages.INVALID_USERNAME;
  }
}
