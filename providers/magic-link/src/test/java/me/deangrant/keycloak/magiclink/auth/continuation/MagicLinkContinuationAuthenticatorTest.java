package me.deangrant.keycloak.magiclink.auth.continuation;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkContinuationAuthenticatorTest {

  @Mock private AuthenticationFlowContext context;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private KeycloakSession session;
  @Mock private RealmModel realm;
  @Mock private UserProvider users;
  @Mock private UserModel user;
  @Mock private HttpRequest httpRequest;
  @Mock private LoginFormsProvider forms;
  @Mock private EventBuilder event;
  @Mock private EventBuilder newEvent;
  @Mock private Response formResponse;

  @Test
  void completesWhenSessionConfirmed() {
    MagicLinkContinuationAuthenticator authenticator = new MagicLinkContinuationAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_EXPIRATION)).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_CONFIRMED)).thenReturn("true");
    when(authSession.getAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME))
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

  @Test
  void unknownEmailUsesContinuationWaitingTemplate() {
    MagicLinkContinuationAuthenticator authenticator = new MagicLinkContinuationAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getEvent()).thenReturn(event);
    when(context.newEvent()).thenReturn(newEvent);
    when(context.form()).thenReturn(forms);
    when(context.getAuthenticatorConfig()).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_EXPIRATION)).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_CONFIRMED)).thenReturn(null);
    when(session.users()).thenReturn(users);
    when(realm.isLoginWithEmailAllowed()).thenReturn(true);
    when(users.getUserByEmail(realm, "missing@example.com")).thenReturn(null);
    when(users.getUserByUsername(realm, "missing@example.com")).thenReturn(null);
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.event(any())).thenReturn(event);
    when(forms.createForm("view-email-continuation.ftl")).thenReturn(formResponse);

    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(AuthenticationManager.FORM_USERNAME, "missing@example.com");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    verify(authSession)
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, "missing@example.com");
    verify(authSession).setAuthNote(ContinuationNotes.SESSION_INITIATED, "true");
    verify(authSession).setAuthNote(eq(ContinuationNotes.SESSION_EXPIRATION), any());
    verify(forms).createForm("view-email-continuation.ftl");
    verify(forms, never()).createForm("view-email.ftl");
    verify(context).forceChallenge(formResponse);
    verify(event).event(EventType.LOGIN_ERROR);
    verify(users, never()).addUser(any(), any());
  }
}
