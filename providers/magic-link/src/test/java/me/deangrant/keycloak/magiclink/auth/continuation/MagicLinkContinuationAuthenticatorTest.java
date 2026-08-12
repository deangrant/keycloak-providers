package me.deangrant.keycloak.magiclink.auth.continuation;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MagicLinkContinuationAuthenticatorTest {

  @Mock private AuthenticationFlowContext context;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private KeycloakSession session;
  @Mock private RealmModel realm;
  @Mock private UserProvider users;
  @Mock private UserModel user;

  @Test
  void completesWhenSessionConfirmed() {
    MagicLinkContinuationAuthenticator authenticator = new MagicLinkContinuationAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_EXPIRATION)).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_CONFIRMED)).thenReturn("true");
    when(authSession.getAuthNote(
            org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator
                .ATTEMPTED_USERNAME))
        .thenReturn("alice@example.com");
    when(session.users()).thenReturn(users);
    when(users.getUserByEmail(realm, "alice@example.com")).thenReturn(user);

    authenticator.authenticate(context);

    verify(context).setUser(user);
    verify(authSession).setAuthenticatedUser(user);
    verify(context).success();
  }

  @Test
  void treatsPastExpirationAsExpired() {
    org.junit.jupiter.api.Assertions.assertTrue(
        MagicLinkContinuationAuthenticator.isExpirationElapsed(
            ZonedDateTime.now(ZoneOffset.UTC).minusMinutes(1).toString()));
    org.junit.jupiter.api.Assertions.assertFalse(
        MagicLinkContinuationAuthenticator.isExpirationElapsed(
            ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(5).toString()));
    org.junit.jupiter.api.Assertions.assertFalse(
        MagicLinkContinuationAuthenticator.isExpirationElapsed(null));
  }
}
