package me.deangrant.keycloak.magiclink.auth.continuation;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.MockedStatic;
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
  @Mock private KeycloakContext keycloakContext;
  @Mock private ClientModel client;
  @Mock private BruteForceProtector protector;
  @Mock private org.keycloak.models.AuthenticationExecutionModel execution;

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

  @Test
  void disabledUserUsesContinuationWaitingTemplate() {
    MagicLinkContinuationAuthenticator authenticator = new MagicLinkContinuationAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getEvent()).thenReturn(event);
    when(context.newEvent()).thenReturn(newEvent);
    when(context.form()).thenReturn(forms);
    when(context.getAuthenticatorConfig()).thenReturn(null);
    when(context.getProtector()).thenReturn(protector);
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn("exec-1");
    when(authSession.getAuthNote(ContinuationNotes.SESSION_EXPIRATION)).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_CONFIRMED)).thenReturn(null);
    when(session.users()).thenReturn(users);
    when(realm.isLoginWithEmailAllowed()).thenReturn(true);
    when(realm.isBruteForceProtected()).thenReturn(false);
    when(users.getUserByEmail(realm, "disabled@example.com")).thenReturn(user);
    when(user.getEmail()).thenReturn("disabled@example.com");
    when(user.isEnabled()).thenReturn(false);
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.event(any())).thenReturn(event);
    when(forms.createForm("view-email-continuation.ftl")).thenReturn(formResponse);
    when(forms.setExecution(any())).thenReturn(forms);
    when(forms.setError(any(), any())).thenReturn(forms);
    when(forms.setError(any())).thenReturn(forms);
    when(forms.addError(any())).thenReturn(forms);

    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(AuthenticationManager.FORM_USERNAME, "disabled@example.com");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    verify(authSession)
        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, "disabled@example.com");
    verify(authSession).setAuthNote(ContinuationNotes.SESSION_INITIATED, "true");
    verify(authSession).setAuthNote(eq(ContinuationNotes.SESSION_EXPIRATION), any());
    verify(forms).createForm("view-email-continuation.ftl");
    verify(forms, never()).createForm("view-email.ftl");
    verify(context).forceChallenge(formResponse);
  }

  @Test
  void smtpFailureDoesNotInitiateContinuationWaiting() {
    MagicLinkContinuationAuthenticator authenticator = new MagicLinkContinuationAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getEvent()).thenReturn(event);
    when(context.newEvent()).thenReturn(newEvent);
    when(context.form()).thenReturn(forms);
    when(context.getAuthenticatorConfig()).thenReturn(null);
    when(context.getProtector()).thenReturn(protector);
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn("exec-1");
    when(authSession.getAuthNote(ContinuationNotes.SESSION_EXPIRATION)).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_CONFIRMED)).thenReturn(null);
    when(session.users()).thenReturn(users);
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getClient()).thenReturn(client);
    when(client.getClientId()).thenReturn("account");
    when(realm.isLoginWithEmailAllowed()).thenReturn(true);
    when(realm.isBruteForceProtected()).thenReturn(false);
    when(users.getUserByEmail(realm, "alice@example.com")).thenReturn(user);
    when(user.getEmail()).thenReturn("alice@example.com");
    when(user.isEnabled()).thenReturn(true);
    when(user.getId()).thenReturn("user-1");
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.event(any())).thenReturn(event);
    when(event.user(user)).thenReturn(event);
    when(forms.createLoginUsername()).thenReturn(formResponse);
    when(forms.setExecution(any())).thenReturn(forms);
    when(forms.setError(any(), any())).thenReturn(forms);
    when(forms.setError(any())).thenReturn(forms);
    when(forms.addError(any())).thenReturn(forms);

    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(AuthenticationManager.FORM_USERNAME, "alice@example.com");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    MagicLinkContinuationActionToken token =
        new MagicLinkContinuationActionToken(
            "user-1", 1000, "account", "root", "tab", "https://app/callback");

    try (MockedStatic<MagicLinkSupport> support =
        mockStatic(MagicLinkSupport.class, CALLS_REAL_METHODS)) {
      support
          .when(() -> MagicLinkSupport.createContinuationToken(any(), any(), anyInt(), any()))
          .thenReturn(token);
      support
          .when(() -> MagicLinkSupport.linkFromActionToken(any(), any(), any()))
          .thenReturn("https://example/continuation");
      support
          .when(() -> MagicLinkSupport.sendContinuationEmail(any(), any(), any()))
          .thenReturn(false);

      authenticator.action(context);

      support.verify(
          () -> MagicLinkSupport.rememberLatestActionToken(any(), any(), anyInt()), never());
    }

    verify(authSession, never()).setAuthNote(eq(ContinuationNotes.SESSION_INITIATED), any());
    verify(forms, never()).createForm("view-email-continuation.ftl");
    verify(event).error(Errors.EMAIL_SEND_FAILED);
    verify(context)
        .failureChallenge(
            eq(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR), eq(formResponse));
  }

  @Test
  void successfulSendRemembersLatestToken() {
    MagicLinkContinuationAuthenticator authenticator = new MagicLinkContinuationAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getEvent()).thenReturn(event);
    when(context.newEvent()).thenReturn(newEvent);
    when(context.form()).thenReturn(forms);
    when(context.getAuthenticatorConfig()).thenReturn(null);
    when(context.getProtector()).thenReturn(protector);
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn("exec-1");
    when(authSession.getAuthNote(ContinuationNotes.SESSION_EXPIRATION)).thenReturn(null);
    when(authSession.getAuthNote(ContinuationNotes.SESSION_CONFIRMED)).thenReturn(null);
    when(session.users()).thenReturn(users);
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getClient()).thenReturn(client);
    when(client.getClientId()).thenReturn("account");
    when(realm.isLoginWithEmailAllowed()).thenReturn(true);
    when(realm.isBruteForceProtected()).thenReturn(false);
    when(users.getUserByEmail(realm, "alice@example.com")).thenReturn(user);
    when(user.getEmail()).thenReturn("alice@example.com");
    when(user.isEnabled()).thenReturn(true);
    when(user.getId()).thenReturn("user-1");
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.event(any())).thenReturn(event);
    when(event.user(user)).thenReturn(event);
    when(forms.createForm("view-email-continuation.ftl")).thenReturn(formResponse);

    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(AuthenticationManager.FORM_USERNAME, "alice@example.com");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    MagicLinkContinuationActionToken token =
        new MagicLinkContinuationActionToken(
            "user-1", 1000, "account", "root", "tab", "https://app/callback");

    try (MockedStatic<MagicLinkSupport> support =
        mockStatic(MagicLinkSupport.class, CALLS_REAL_METHODS)) {
      support
          .when(() -> MagicLinkSupport.createContinuationToken(any(), any(), anyInt(), any()))
          .thenReturn(token);
      support
          .when(() -> MagicLinkSupport.linkFromActionToken(any(), any(), any()))
          .thenReturn("https://example/continuation");
      support
          .when(() -> MagicLinkSupport.sendContinuationEmail(any(), any(), any()))
          .thenReturn(true);

      authenticator.action(context);

      support.verify(() -> MagicLinkSupport.rememberLatestActionToken(session, token, 60 * 10));
    }

    verify(forms).createForm("view-email-continuation.ftl");
    verify(context).challenge(formResponse);
  }
}
