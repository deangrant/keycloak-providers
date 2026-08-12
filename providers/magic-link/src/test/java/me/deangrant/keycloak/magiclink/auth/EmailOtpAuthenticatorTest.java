package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.util.Time;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailOtpAuthenticatorTest {

  @Mock private AuthenticationFlowContext context;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private UserModel user;
  @Mock private HttpRequest httpRequest;
  @Mock private LoginFormsProvider forms;
  @Mock private AuthenticationExecutionModel execution;
  @Mock private EventBuilder event;
  @Mock private Response formResponse;
  @Mock private RealmModel realm;
  @Mock private KeycloakSession session;
  @Mock private BruteForceProtector protector;

  private EmailOtpAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    authenticator = new EmailOtpAuthenticator();
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getUser()).thenReturn(user);
    when(context.form()).thenReturn(forms);
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn("exec-1");
    when(forms.setExecution(any())).thenReturn(forms);
    when(forms.setErrors(any())).thenReturn(forms);
    when(forms.createForm("otp-form.ftl")).thenReturn(formResponse);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getEvent()).thenReturn(event);
    when(event.user(user)).thenReturn(event);
    when(event.event(any())).thenReturn(event);
    when(context.getRealm()).thenReturn(realm);
    when(context.getSession()).thenReturn(session);
    when(context.getProtector()).thenReturn(protector);
    when(realm.isBruteForceProtected()).thenReturn(false);
  }

  @Test
  void acceptsMatchingCodeBeforeExpiry() {
    String code = "123456";
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH))
        .thenReturn(EmailOtpAuthenticator.hash(code));
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY))
        .thenReturn(String.valueOf(Time.currentTime() + 60));
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(EmailOtpAuthenticator.FORM_PARAM_OTP, code);
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);
    when(authSession.getAuthenticatedUser()).thenReturn(user);

    authenticator.action(context);

    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH);
    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY);
    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS);
    verify(user).setEmailVerified(true);
    verify(context).success();
  }

  @Test
  void rejectsWrongCodeAndIncrementsAttempts() {
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH))
        .thenReturn(EmailOtpAuthenticator.hash("123456"));
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY))
        .thenReturn(String.valueOf(Time.currentTime() + 60));
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS)).thenReturn(null);
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(EmailOtpAuthenticator.FORM_PARAM_OTP, "000000");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    verify(authSession).setAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS, "1");
    verify(context)
        .failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(formResponse));
    verify(context, never()).success();
  }

  @Test
  void invalidatesCodeWhenMaxAttemptsReached() {
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH))
        .thenReturn(EmailOtpAuthenticator.hash("123456"));
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY))
        .thenReturn(String.valueOf(Time.currentTime() + 60));
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS)).thenReturn("4");
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(EmailOtpAuthenticator.FORM_PARAM_OTP, "000000");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH);
    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY);
    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS);
    verify(authSession, never())
        .setAuthNote(eq(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS), any());
    verify(context)
        .failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(formResponse));
    verify(context, never()).success();
  }

  @Test
  void rejectsWhenAttemptsAlreadyAtMax() {
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS)).thenReturn("5");
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(EmailOtpAuthenticator.FORM_PARAM_OTP, "123456");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH);
    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY);
    verify(authSession).removeAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_ATTEMPTS);
    verify(context)
        .failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), eq(formResponse));
    verify(context, never()).success();
  }

  @Test
  void rejectsExpiredCode() {
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH))
        .thenReturn(EmailOtpAuthenticator.hash("123456"));
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_EXPIRY))
        .thenReturn(String.valueOf(Time.currentTime() - 10));
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(EmailOtpAuthenticator.FORM_PARAM_OTP, "123456");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    ArgumentCaptor<AuthenticationFlowError> error =
        ArgumentCaptor.forClass(AuthenticationFlowError.class);
    verify(context).failureChallenge(error.capture(), eq(formResponse));
    assertEquals(AuthenticationFlowError.EXPIRED_CODE, error.getValue());
  }

  @Test
  void forceChallengesWhenBruteForceLocked() {
    when(realm.isBruteForceProtected()).thenReturn(true);
    when(protector.isPermanentlyLockedOut(session, realm, user)).thenReturn(false);
    when(protector.isTemporarilyDisabled(session, realm, user)).thenReturn(true);
    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(EmailOtpAuthenticator.FORM_PARAM_OTP, "123456");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    authenticator.action(context);

    verify(event).error(Errors.USER_TEMPORARILY_DISABLED);
    verify(context).forceChallenge(formResponse);
    verify(context, never()).success();
    verify(context, never()).failureChallenge(any(), any());
  }

  @Test
  void smtpFailureShowsEmailSendErrorOnOtpForm() {
    when(authSession.getAuthNote(EmailOtpAuthenticator.AUTH_NOTE_OTP_HASH)).thenReturn(null);
    when(user.getEmail()).thenReturn("alice@example.com");

    try (MockedStatic<MagicLinkSupport> support =
        mockStatic(MagicLinkSupport.class, CALLS_REAL_METHODS)) {
      support.when(() -> MagicLinkSupport.sendOtpEmail(any(), any(), any())).thenReturn(false);
      authenticator.authenticate(context);
    }

    verify(event).error(Errors.EMAIL_SEND_FAILED);
    verify(context)
        .failureChallenge(
            eq(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR), eq(formResponse));
    verify(context, never()).challenge(any());
  }
}
