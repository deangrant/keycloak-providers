package me.deangrant.keycloak.magiclink.auth.continuation;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.jboss.logging.Logger;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.TokenUtils;
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
    // Click device must not join the original waiting tab's auth session.
    AuthenticationSessionModel authSession =
        tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
    authSession.setAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS, "true");
    return authSession;
  }

  @Override
  public boolean canUseTokenRepeatedly(
      MagicLinkContinuationActionToken token,
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    return false;
  }

  @Override
  public TokenVerifier.Predicate<? super MagicLinkContinuationActionToken>[] getVerifiers(
      ActionTokenContext<MagicLinkContinuationActionToken> tokenContext) {
    return TokenUtils.predicates(
        TokenUtils.checkThat(
            token -> MagicLinkSupport.isLatestActionToken(tokenContext.getSession(), token),
            Errors.EXPIRED_CODE,
            Messages.EXPIRED_ACTION_TOKEN_NO_SESSION));
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
    ClientModel client =
        MagicLinkSupport.resolveClient(
            session, tokenContext.getRealm(), authSession, token.getIssuedFor());
    AuthenticationSessionProvider provider = session.authenticationSessions();
    RootAuthenticationSessionModel root =
        provider.getRootAuthenticationSession(tokenContext.getRealm(), token.getSessionId());
    LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class);

    if (client == null) {
      LOG.warnf(
          "Continuation handler missing client for user %s issuedFor %s",
          token.getUserId(), token.getIssuedFor());
      tokenContext.getEvent().error(Errors.CLIENT_NOT_FOUND);
      return forms.setActionUri(URI.create("#")).createForm("email-confirmation-error.ftl");
    }

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
