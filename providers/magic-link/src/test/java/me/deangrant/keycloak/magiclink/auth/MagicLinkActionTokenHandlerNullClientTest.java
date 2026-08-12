package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkActionTokenHandlerNullClientTest {

  @Mock private MagicLinkActionToken token;
  @Mock private ActionTokenContext<MagicLinkActionToken> tokenContext;
  @Mock private KeycloakSession session;
  @Mock private KeycloakContext keycloakContext;
  @Mock private RealmModel realm;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private ClientProvider clients;
  @Mock private UserModel user;
  @Mock private EventBuilder event;
  @Mock private Response errorResponse;

  @Test
  void handleTokenReturnsErrorWhenClientMissing() {
    MagicLinkActionTokenHandler handler = new MagicLinkActionTokenHandler();
    when(tokenContext.getSession()).thenReturn(session);
    when(tokenContext.getRealm()).thenReturn(realm);
    when(tokenContext.getAuthenticationSession()).thenReturn(authSession);
    when(tokenContext.getEvent()).thenReturn(event);
    when(session.getContext()).thenReturn(keycloakContext);
    when(session.clients()).thenReturn(clients);
    when(authSession.getClient()).thenReturn(null);
    when(authSession.getAuthenticatedUser()).thenReturn(user);
    when(keycloakContext.getClient()).thenReturn(null);
    when(token.getIssuedFor()).thenReturn("missing-client");
    when(token.getUserId()).thenReturn("user-1");
    when(clients.getClientByClientId(realm, "missing-client")).thenReturn(null);

    try (MockedStatic<ErrorPage> errorPage = mockStatic(ErrorPage.class)) {
      errorPage
          .when(
              () ->
                  ErrorPage.error(
                      session, authSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST))
          .thenReturn(errorResponse);

      Response response = handler.handleToken(token, tokenContext);

      assertSame(errorResponse, response);
      verify(event).error(Errors.CLIENT_NOT_FOUND);
    }
  }
}
