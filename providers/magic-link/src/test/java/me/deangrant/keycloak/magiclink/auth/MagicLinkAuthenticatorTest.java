package me.deangrant.keycloak.magiclink.auth;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import me.deangrant.keycloak.magiclink.spi.MagicLinkCustomizationProvider;
import me.deangrant.keycloak.magiclink.spi.MagicLinkCustomizationProviderFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
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
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkAuthenticatorTest {

  @Mock private AuthenticationFlowContext context;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private KeycloakSession session;
  @Mock private KeycloakContext keycloakContext;
  @Mock private ClientModel client;
  @Mock private RealmModel realm;
  @Mock private UserProvider users;
  @Mock private UserModel createdUser;
  @Mock private HttpRequest httpRequest;
  @Mock private LoginFormsProvider forms;
  @Mock private EventBuilder event;
  @Mock private Response formResponse;
  @Mock private AuthenticatorConfigModel authenticatorConfig;
  @Mock private BruteForceProtector protector;

  @BeforeEach
  void setUp() {
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getEvent()).thenReturn(event);
    when(context.form()).thenReturn(forms);
    when(context.getProtector()).thenReturn(protector);
    when(session.getContext()).thenReturn(keycloakContext);
    when(session.users()).thenReturn(users);
    when(keycloakContext.getClient()).thenReturn(client);
    when(client.getClientId()).thenReturn("account");
    when(realm.isLoginWithEmailAllowed()).thenReturn(true);
    when(realm.isBruteForceProtected()).thenReturn(false);
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.event(any())).thenReturn(event);
    when(forms.createForm("view-email.ftl")).thenReturn(formResponse);
  }

  @Test
  void unknownEmailUsesWaitingTemplateToAvoidEnumeration() {
    when(context.getAuthenticatorConfig()).thenReturn(null);
    when(users.getUserByEmail(realm, "missing@example.com")).thenReturn(null);
    when(users.getUserByUsername(realm, "missing@example.com")).thenReturn(null);

    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(AuthenticationManager.FORM_USERNAME, "missing@example.com");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    MagicLinkAuthenticator authenticator =
        new MagicLinkAuthenticator((s, config) -> new DefaultAllowProvider());
    authenticator.action(context);

    verify(forms).createForm("view-email.ftl");
    verify(context).forceChallenge(formResponse);
    verify(event).event(EventType.LOGIN_ERROR);
    verify(users, never()).addUser(any(), any());
    verify(context, never()).challenge(any());
  }

  @Test
  void forceCreateRollbackWhenCustomizationDenies() {
    when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
    when(authenticatorConfig.getConfig()).thenReturn(Map.of(MagicLinkConfig.FORCE_CREATE, "true"));
    when(users.getUserByEmail(realm, "new@example.com")).thenReturn(null);
    when(users.getUserByUsername(realm, "new@example.com")).thenReturn(null);
    when(users.addUser(realm, "new@example.com")).thenReturn(createdUser);
    when(createdUser.getEmail()).thenReturn("new@example.com");
    when(createdUser.isEnabled()).thenReturn(true);

    MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
    form.add(AuthenticationManager.FORM_USERNAME, "new@example.com");
    when(httpRequest.getDecodedFormParameters()).thenReturn(form);

    MagicLinkCustomizationProvider denyProvider =
        new MagicLinkCustomizationProvider() {
          @Override
          public boolean canAuthenticate(
              AuthenticationFlowContext context, UserModel user, MagicLinkConfig config) {
            return false;
          }

          @Override
          public boolean sendMagicLinkEmail(
              KeycloakSession session, UserModel user, String link, MagicLinkConfig config) {
            return true;
          }

          @Override
          public void close() {}
        };
    MagicLinkCustomizationProviderFactory factory = (s, config) -> denyProvider;

    MagicLinkAuthenticator authenticator = new MagicLinkAuthenticator(factory);
    authenticator.action(context);

    verify(users).addUser(realm, "new@example.com");
    verify(users).removeUser(realm, createdUser);
    verify(context, never()).challenge(any());
    verify(context, never()).forceChallenge(any());
  }

  private static final class DefaultAllowProvider implements MagicLinkCustomizationProvider {
    @Override
    public boolean canAuthenticate(
        AuthenticationFlowContext context, UserModel user, MagicLinkConfig config) {
      return true;
    }

    @Override
    public boolean sendMagicLinkEmail(
        KeycloakSession session, UserModel user, String link, MagicLinkConfig config) {
      return true;
    }

    @Override
    public void close() {}
  }
}
