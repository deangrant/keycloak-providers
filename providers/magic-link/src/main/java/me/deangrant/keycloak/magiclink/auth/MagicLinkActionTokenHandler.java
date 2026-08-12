package me.deangrant.keycloak.magiclink.auth;

import jakarta.ws.rs.core.Response;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.authentication.actiontoken.TokenUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.sessions.AuthenticationSessionModel;

/** Completes login when a magic-link action token is opened. */
public final class MagicLinkActionTokenHandler
    extends AbstractActionTokenHandler<MagicLinkActionToken> {

  private static final Logger LOG = Logger.getLogger(MagicLinkActionTokenHandler.class);

  /** User-session note key recording that authentication completed via magic link. */
  public static final String LOGIN_METHOD = "login_method";

  public MagicLinkActionTokenHandler() {
    super(
        MagicLinkActionToken.TOKEN_TYPE,
        MagicLinkActionToken.class,
        Messages.INVALID_REQUEST,
        EventType.EXECUTE_ACTION_TOKEN,
        Errors.INVALID_REQUEST);
  }

  @Override
  public AuthenticationSessionModel startFreshAuthenticationSession(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return tokenContext.createAuthenticationSessionForClient(token.getIssuedFor());
  }

  @Override
  public boolean canUseTokenRepeatedly(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return false;
  }

  @Override
  public TokenVerifier.Predicate<? super MagicLinkActionToken>[] getVerifiers(
      ActionTokenContext<MagicLinkActionToken> tokenContext) {
    return TokenUtils.predicates(
        TokenUtils.checkThat(
            token -> MagicLinkSupport.isLatestActionToken(tokenContext.getSession(), token),
            Errors.EXPIRED_CODE,
            Messages.EXPIRED_ACTION_TOKEN_NO_SESSION));
  }

  @Override
  public Response handleToken(
      MagicLinkActionToken token, ActionTokenContext<MagicLinkActionToken> tokenContext) {
    LOG.debugf(
        "Handling magic link for user %s client %s", token.getUserId(), token.getIssuedFor());

    AuthenticationSessionModel authSession = tokenContext.getAuthenticationSession();
    UserModel user = authSession.getAuthenticatedUser();
    ClientModel client =
        MagicLinkSupport.resolveClient(
            tokenContext.getSession(), tokenContext.getRealm(), authSession, token.getIssuedFor());
    if (client == null) {
      LOG.warnf(
          "Magic link handler missing client for user %s issuedFor %s",
          token.getUserId(), token.getIssuedFor());
      tokenContext.getEvent().error(Errors.CLIENT_NOT_FOUND);
      return ErrorPage.error(
          tokenContext.getSession(),
          authSession,
          Response.Status.BAD_REQUEST,
          Messages.INVALID_REQUEST);
    }

    String redirectUri =
        token.getRedirectUri() != null
            ? token.getRedirectUri()
            : ResolveRelative.resolveRelativeUri(
                tokenContext.getSession(), client.getRootUrl(), client.getBaseUrl());

    if (redirectUri != null) {
      String verified =
          RedirectUtils.verifyRedirectUri(tokenContext.getSession(), redirectUri, client);
      if (verified == null) {
        LOG.warnf(
            "Magic link rejected invalid redirect URI for user %s client %s",
            token.getUserId(), token.getIssuedFor());
        tokenContext.getEvent().error(Errors.INVALID_REDIRECT_URI);
        return ErrorPage.error(
            tokenContext.getSession(),
            authSession,
            Response.Status.BAD_REQUEST,
            Messages.INVALID_REDIRECT_URI);
      }
      authSession.setAuthNote(
          AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
      authSession.setRedirectUri(verified);
      authSession.setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, redirectUri);
      if (token.getState() != null) {
        authSession.setClientNote(OIDCLoginProtocol.STATE_PARAM, token.getState());
      }
      if (token.getNonce() != null) {
        authSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
        authSession.setUserSessionNote(OIDCLoginProtocol.NONCE_PARAM, token.getNonce());
      }
      if (token.getCodeChallenge() != null) {
        authSession.setClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM, token.getCodeChallenge());
      }
      if (token.getCodeChallengeMethod() != null) {
        authSession.setClientNote(
            OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM, token.getCodeChallengeMethod());
      }
    }

    if (token.getScope() != null) {
      authSession.setClientNote(OAuth2Constants.SCOPE, token.getScope());
      AuthenticationManager.setClientScopesInSession(tokenContext.getSession(), authSession);
    }

    if (Boolean.TRUE.equals(token.getRememberMe()) && tokenContext.getRealm().isRememberMe()) {
      authSession.setAuthNote(Details.REMEMBER_ME, "true");
      tokenContext.getEvent().detail(Details.REMEMBER_ME, "true");
    } else {
      authSession.removeAuthNote(Details.REMEMBER_ME);
    }

    String responseMode = MagicLinkSupport.trimToNull(token.getResponseMode());
    if (responseMode != null) {
      authSession.setClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM, responseMode);
    }

    user.setEmailVerified(true);
    authSession.setUserSessionNote(LOGIN_METHOD, MagicLinkAuthenticatorFactory.PROVIDER_ID);

    String nextAction =
        AuthenticationManager.nextRequiredAction(
            tokenContext.getSession(),
            authSession,
            tokenContext.getRequest(),
            tokenContext.getEvent());
    return AuthenticationManager.redirectToRequiredActions(
        tokenContext.getSession(),
        tokenContext.getRealm(),
        authSession,
        tokenContext.getUriInfo(),
        nextAction);
  }
}
