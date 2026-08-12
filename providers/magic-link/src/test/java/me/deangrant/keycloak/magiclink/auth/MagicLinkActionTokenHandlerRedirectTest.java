package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.Response;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkActionTokenHandlerRedirectTest {

  @Mock private MagicLinkActionToken token;
  @Mock private ActionTokenContext<MagicLinkActionToken> tokenContext;
  @Mock private KeycloakSession session;
  @Mock private RealmModel realm;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private ClientModel client;
  @Mock private UserModel user;
  @Mock private EventBuilder event;
  @Mock private HttpRequest request;
  @Mock private Response errorResponse;
  @Mock private Response successResponse;

  private MagicLinkActionTokenHandler handler;

  @BeforeEach
  void setUp() {
    handler = new MagicLinkActionTokenHandler();
    when(tokenContext.getSession()).thenReturn(session);
    when(tokenContext.getRealm()).thenReturn(realm);
    when(tokenContext.getAuthenticationSession()).thenReturn(authSession);
    when(tokenContext.getEvent()).thenReturn(event);
    when(tokenContext.getRequest()).thenReturn(request);
    when(tokenContext.getUriInfo()).thenReturn(null);
    when(authSession.getAuthenticatedUser()).thenReturn(user);
    when(authSession.getClient()).thenReturn(client);
    when(token.getIssuedFor()).thenReturn("account");
    when(token.getUserId()).thenReturn("user-1");
    when(token.getRedirectUri()).thenReturn("https://evil.example/callback");
    when(token.getRememberMe()).thenReturn(false);
    when(realm.isRememberMe()).thenReturn(false);
  }

  @Test
  void handleTokenAbortsWhenRedirectVerificationFails() {
    try (MockedStatic<MagicLinkSupport> support =
            mockStatic(MagicLinkSupport.class, CALLS_REAL_METHODS);
        MockedStatic<RedirectUtils> redirects = mockStatic(RedirectUtils.class);
        MockedStatic<ErrorPage> errorPage = mockStatic(ErrorPage.class);
        MockedStatic<AuthenticationManager> authManager = mockStatic(AuthenticationManager.class)) {
      support
          .when(() -> MagicLinkSupport.resolveClient(session, realm, authSession, "account"))
          .thenReturn(client);
      redirects
          .when(
              () ->
                  RedirectUtils.verifyRedirectUri(session, "https://evil.example/callback", client))
          .thenReturn(null);
      errorPage
          .when(
              () ->
                  ErrorPage.error(
                      session,
                      authSession,
                      Response.Status.BAD_REQUEST,
                      Messages.INVALID_REDIRECT_URI))
          .thenReturn(errorResponse);

      Response response = handler.handleToken(token, tokenContext);

      assertSame(errorResponse, response);
      verify(event).error(Errors.INVALID_REDIRECT_URI);
      verify(user, never()).setEmailVerified(true);
      authManager.verify(
          () -> AuthenticationManager.redirectToRequiredActions(any(), any(), any(), any(), any()),
          never());
    }
  }

  @Test
  void handleTokenSetsRedirectNotesWhenVerificationSucceeds() {
    when(token.getRedirectUri()).thenReturn("https://app.example/callback");
    when(token.getState()).thenReturn("state-1");
    when(token.getResponseMode()).thenReturn("query");

    try (MockedStatic<MagicLinkSupport> support =
            mockStatic(MagicLinkSupport.class, CALLS_REAL_METHODS);
        MockedStatic<RedirectUtils> redirects = mockStatic(RedirectUtils.class);
        MockedStatic<AuthenticationManager> authManager = mockStatic(AuthenticationManager.class)) {
      support
          .when(() -> MagicLinkSupport.resolveClient(session, realm, authSession, "account"))
          .thenReturn(client);
      redirects
          .when(
              () ->
                  RedirectUtils.verifyRedirectUri(session, "https://app.example/callback", client))
          .thenReturn("https://app.example/callback");
      authManager
          .when(
              () -> AuthenticationManager.nextRequiredAction(session, authSession, request, event))
          .thenReturn(null);
      authManager
          .when(
              () ->
                  AuthenticationManager.redirectToRequiredActions(
                      session, realm, authSession, null, null))
          .thenReturn(successResponse);

      Response response = handler.handleToken(token, tokenContext);

      assertSame(successResponse, response);
      verify(authSession)
          .setAuthNote(AuthenticationManager.SET_REDIRECT_URI_AFTER_REQUIRED_ACTIONS, "true");
      verify(authSession).setRedirectUri("https://app.example/callback");
      verify(authSession)
          .setClientNote(OIDCLoginProtocol.REDIRECT_URI_PARAM, "https://app.example/callback");
      verify(authSession).setClientNote(OIDCLoginProtocol.STATE_PARAM, "state-1");
      verify(authSession).setClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM, "query");
      verify(user).setEmailVerified(true);
      verify(event, never()).error(eq(Errors.INVALID_REDIRECT_URI));
    }
  }

  @Test
  void handleTokenSkipsBlankResponseMode() {
    when(token.getRedirectUri()).thenReturn("https://app.example/callback");
    when(token.getResponseMode()).thenReturn("  ");

    try (MockedStatic<MagicLinkSupport> support =
            mockStatic(MagicLinkSupport.class, CALLS_REAL_METHODS);
        MockedStatic<RedirectUtils> redirects = mockStatic(RedirectUtils.class);
        MockedStatic<AuthenticationManager> authManager = mockStatic(AuthenticationManager.class)) {
      support
          .when(() -> MagicLinkSupport.resolveClient(session, realm, authSession, "account"))
          .thenReturn(client);
      redirects
          .when(
              () ->
                  RedirectUtils.verifyRedirectUri(session, "https://app.example/callback", client))
          .thenReturn("https://app.example/callback");
      authManager
          .when(
              () -> AuthenticationManager.nextRequiredAction(session, authSession, request, event))
          .thenReturn(null);
      authManager
          .when(
              () ->
                  AuthenticationManager.redirectToRequiredActions(
                      session, realm, authSession, null, null))
          .thenReturn(successResponse);

      assertSame(successResponse, handler.handleToken(token, tokenContext));
      verify(authSession, never()).setClientNote(eq(OIDCLoginProtocol.RESPONSE_MODE_PARAM), any());
    }
  }
}
