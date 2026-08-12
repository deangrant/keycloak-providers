package me.deangrant.keycloak.magiclink.auth.continuation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.UUID;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.AuthenticationSessionProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkContinuationActionTokenHandlerTest {

  @Mock private MagicLinkContinuationActionToken token;
  @Mock private ActionTokenContext<MagicLinkContinuationActionToken> tokenContext;
  @Mock private KeycloakSession session;
  @Mock private RealmModel realm;
  @Mock private ClientModel client;
  @Mock private ClientProvider clients;
  @Mock private AuthenticationSessionProvider authSessions;
  @Mock private RootAuthenticationSessionModel root;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private AuthenticationSessionModel originalSession;
  @Mock private AuthenticationSessionModel freshSession;
  @Mock private UserModel user;
  @Mock private LoginFormsProvider forms;
  @Mock private EventBuilder event;
  @Mock private Response confirmationResponse;
  @Mock private Response errorResponse;

  private MagicLinkContinuationActionTokenHandler handler;

  @BeforeEach
  void setUp() {
    handler = new MagicLinkContinuationActionTokenHandler();
    when(tokenContext.getSession()).thenReturn(session);
    when(tokenContext.getRealm()).thenReturn(realm);
    when(tokenContext.getEvent()).thenReturn(event);
    when(tokenContext.getAuthenticationSession()).thenReturn(authSession);
    when(session.authenticationSessions()).thenReturn(authSessions);
    when(session.clients()).thenReturn(clients);
    when(session.getProvider(LoginFormsProvider.class)).thenReturn(forms);
    when(authSession.getClient()).thenReturn(client);
    when(authSession.getAuthenticatedUser()).thenReturn(user);
    when(token.getSessionId()).thenReturn("root-session");
    when(token.getTabId()).thenReturn("tab-1");
    when(token.getIssuedFor()).thenReturn("account");
    when(token.getRedirectUri()).thenReturn("https://app.example/callback");
    when(token.getUserId()).thenReturn("user-1");
    when(forms.setActionUri(any())).thenReturn(forms);
    when(forms.setAttribute(any(), any())).thenReturn(forms);
  }

  @Test
  void continuationTokensAreSingleUse() {
    assertFalse(handler.canUseTokenRepeatedly(token, tokenContext));
  }

  @Test
  void getVerifiersRejectsSupersededToken() throws Exception {
    UUID latest = UUID.randomUUID();
    UUID older = UUID.randomUUID();
    SingleUseObjectProvider singleUse = org.mockito.Mockito.mock(SingleUseObjectProvider.class);
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUse);
    when(token.getActionId()).thenReturn(MagicLinkContinuationActionToken.TOKEN_TYPE);
    when(token.getActionVerificationNonce()).thenReturn(older);
    when(singleUse.get(MagicLinkSupport.LATEST_CONTINUATION_KEY_PREFIX + "user-1"))
        .thenReturn(Map.of(MagicLinkSupport.LATEST_TOKEN_NONCE, latest.toString()));

    TokenVerifier.Predicate<? super MagicLinkContinuationActionToken>[] verifiers =
        handler.getVerifiers(tokenContext);

    org.junit.jupiter.api.Assertions.assertThrows(
        org.keycloak.common.VerificationException.class, () -> verifiers[0].test(token));
  }

  @Test
  void handleTokenConfirmsOriginalSessionWhenPresent() {
    when(authSessions.getRootAuthenticationSession(realm, "root-session")).thenReturn(root);
    when(root.getAuthenticationSession(client, "tab-1")).thenReturn(originalSession);
    when(forms.createForm("email-confirmation.ftl")).thenReturn(confirmationResponse);

    Response response = handler.handleToken(token, tokenContext);

    assertSame(confirmationResponse, response);
    verify(user).setEmailVerified(true);
    verify(originalSession).setAuthNote(ContinuationNotes.SESSION_CONFIRMED, "true");
    verify(event).success();
    verify(forms).createForm("email-confirmation.ftl");
    verify(forms, never()).createForm("email-confirmation-error.ftl");
  }

  @Test
  void handleTokenShowsErrorWhenOriginalSessionMissing() {
    when(authSessions.getRootAuthenticationSession(realm, "root-session")).thenReturn(null);
    when(forms.createForm("email-confirmation-error.ftl")).thenReturn(errorResponse);

    Response response = handler.handleToken(token, tokenContext);

    assertSame(errorResponse, response);
    verify(event).error("Expired magic link continuation session");
    verify(forms).createForm("email-confirmation-error.ftl");
    verify(forms, never()).createForm("email-confirmation.ftl");
  }

  @Test
  void startFreshAuthenticationSessionDoesNotJoinOriginalTab() {
    when(authSessions.getRootAuthenticationSession(realm, "root-session")).thenReturn(root);
    when(root.getAuthenticationSession(client, "tab-1")).thenReturn(originalSession);
    when(tokenContext.createAuthenticationSessionForClient("account")).thenReturn(freshSession);

    AuthenticationSessionModel result =
        handler.startFreshAuthenticationSession(token, tokenContext);

    assertSame(freshSession, result);
    verify(freshSession).setAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS, "true");
    verify(root, never()).getAuthenticationSession(any(), any());
    verify(root, never()).createAuthenticationSession(any());
  }

  @Test
  void startFreshAuthenticationSessionEndsAfterRequiredActions() {
    when(tokenContext.createAuthenticationSessionForClient("account")).thenReturn(freshSession);

    AuthenticationSessionModel result =
        handler.startFreshAuthenticationSession(token, tokenContext);

    assertSame(freshSession, result);
    verify(freshSession).setAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS, "true");
  }
}
