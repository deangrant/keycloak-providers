package me.deangrant.keycloak.magiclink.auth;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import me.deangrant.keycloak.magiclink.spi.MagicLinkCustomizationProvider;
import me.deangrant.keycloak.magiclink.spi.MagicLinkCustomizationProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

/**
 * Browser-flow authenticator that emails a magic link and waits for the user to open it (possibly
 * on another device).
 */
public final class MagicLinkAuthenticator extends UsernamePasswordForm {

  private static final Logger LOG = Logger.getLogger(MagicLinkAuthenticator.class);

  private final MagicLinkCustomizationProviderFactory customizationProviderFactory;

  MagicLinkAuthenticator(MagicLinkCustomizationProviderFactory customizationProviderFactory) {
    this.customizationProviderFactory = customizationProviderFactory;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String attemptedUsername = MagicLinkSupport.getAttemptedUsername(context);
    if (attemptedUsername == null) {
      super.authenticate(context);
    } else {
      action(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
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

    MagicLinkConfig config = new MagicLinkConfig(context.getAuthenticatorConfig());
    String clientId = context.getSession().getContext().getClient().getClientId();

    MagicLinkSupport.GetOrCreateResult created =
        MagicLinkSupport.getOrCreate(
            context.getSession(),
            context.getRealm(),
            email,
            config.isForceCreate(),
            config.isUpdateProfile(),
            config.isUpdatePassword());
    UserModel user = created.user();

    if (user == null
        || MagicLinkSupport.trimToNull(user.getEmail()) == null
        || !MagicLinkSupport.isValidEmail(user.getEmail())) {
      context
          .getEvent()
          .detail(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email)
          .event(EventType.LOGIN_ERROR)
          .error(Errors.INVALID_EMAIL);
      context
          .getAuthenticationSession()
          .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      // Avoid account enumeration: show the same waiting page.
      context.forceChallenge(context.form().createForm("view-email.ftl"));
      return;
    }

    if (!enabledUser(context, user)) {
      if (created.created()) {
        MagicLinkSupport.removeUser(context.getSession(), context.getRealm(), user);
      }
      // Avoid enumeration / stall: same waiting page as unknown email (no mail).
      context
          .getAuthenticationSession()
          .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
      context.forceChallenge(context.form().createForm("view-email.ftl"));
      return;
    }

    MagicLinkCustomizationProvider customization =
        customizationProviderFactory.create(context.getSession(), config.raw());
    boolean sent = false;
    MagicLinkActionToken token = null;
    try {
      if (!customization.canAuthenticate(context, user, config)) {
        if (created.created()) {
          MagicLinkSupport.removeUser(context.getSession(), context.getRealm(), user);
        }
        // Avoid enumeration / stall: authenticator owns the waiting-page challenge.
        context
            .getAuthenticationSession()
            .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
        context.forceChallenge(context.form().createForm("view-email.ftl"));
        return;
      }

      token =
          MagicLinkSupport.createMagicLinkToken(
              user,
              clientId,
              config.getTokenLifespan(),
              rememberMe(context),
              context.getAuthenticationSession());
      String link =
          MagicLinkSupport.linkFromActionToken(context.getSession(), context.getRealm(), token);
      sent = customization.sendMagicLinkEmail(context.getSession(), user, link, config);
      LOG.debugf("Magic link email to %s sent=%s", user.getEmail(), sent);
    } finally {
      customization.close();
    }

    MagicLinkSupport.finalizeForceCreatedUser(
        context.getSession(),
        context.getRealm(),
        created,
        sent,
        context.newEvent(),
        MagicLinkSupport.REGISTER_METHOD_MAGIC_LINK);

    context
        .getAuthenticationSession()
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, email);
    if (!sent) {
      context.getEvent().user(user).event(EventType.LOGIN_ERROR).error(Errors.EMAIL_SEND_FAILED);
      Response challengeResponse = challenge(context, Messages.EMAIL_SENT_ERROR, FIELD_USERNAME);
      context.failureChallenge(
          AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challengeResponse);
      return;
    }
    int lifespan = config.getTokenLifespan().orElse(15 * 60);
    MagicLinkSupport.rememberLatestActionToken(context.getSession(), token, lifespan);
    context.challenge(context.form().createForm("view-email.ftl"));
  }

  private boolean rememberMe(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    String rememberMe = formData.getFirst("rememberMe");
    return context.getRealm().isRememberMe()
        && rememberMe != null
        && "on".equalsIgnoreCase(rememberMe);
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
