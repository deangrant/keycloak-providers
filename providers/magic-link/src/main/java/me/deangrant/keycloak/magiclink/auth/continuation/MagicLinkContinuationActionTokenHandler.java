package me.deangrant.keycloak.magiclink.auth.continuation;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Marks the original authentication session as confirmed when the continuation magic link is
 * opened. Does not complete login on the click device.
 */
public final class MagicLinkContinuationActionTokenHandler
    extends AbstractActionTokenHandler<MagicLinkContinuationActionToken> {

  private static final Logger LOG = Logger.getLogger(MagicLinkContinuationActionTokenHandler.class);

  public MagicLinkContinuationActionTokenHandler() {
    super(
        MagicLinkContinuationActionToken.TOKEN_TYPE,
        MagicLinkContinuationActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST);
  }

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(
      MagicLinkContinuationActionToken token,
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    ClientModel client =
        tokenContext
            .getSession()
            .clients()
            .getClientByClientId(tokenContext.getRealm(), token.getIssuedFor());
    AuthenticationSessionProvider provider = tokenContext.getSession().authenticationSessions();
    RootAuthenticationSessionModel root =
        provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());
    if (root == null) {
      AuthenticationSessionModel authSession =
          tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
      authSession.setAuthNote(AuthenticationManager.INVALIDATE_ACTION_TOKEN, "true");
      return authSession;
    }

    AuthenticationSessionModel existing = root.getAuthenticationSession(client, token.getTabId());
    if (existing != null) {
      return existing;
    }
    return root.createAuthenticationSession(client);
  }

  @Override
  public boolean canUseTokenRepeatedly(
      MagicLinkContinuationActionToken token,
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    return false;
  }

  @Override
  public Response handleToken(
      MagicLinkContinuationActionToken token,
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    LOG.debugf(
        "Continuation link for user %s session %s tab %s",
        token.getUserId(), token.getSessionId(), token.getTabId());

    AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    UserModel user = authSession.getAuthenticatedUser();
    if (user != null) {
      user.setEmailVerified(true);
    }

    KeycloakSession session = tokenContext.getSession();
    ClientModel client = authSession.getClient();
    AuthenticationSessionProvider provider = session.authenticationSessions();
    RootAuthenticationSessionModel root =
        provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());
    LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class);

    if (root != null) {
      AuthenticationSessionModel original = root.getAuthenticationSession(client, token.getTabId());
      if (original != null) {
        original.setAuthNote(ContinuationNotes.SESSION_CONFIRMED, "true");
        tokenContext.getEvent().success();
        return forms
            .setActionUri(URI.create("#"))
            .setAttribute("redirectUri", token.getRedirectUri())
            .createForm("email-confirmation.ftl");
      }
    }

    tokenContext.getEvent().error("Expired magic link continuation session");
    return forms.setActionUri(URI.create("#")).createForm("email-confirmation-error.ftl");
  }
}
