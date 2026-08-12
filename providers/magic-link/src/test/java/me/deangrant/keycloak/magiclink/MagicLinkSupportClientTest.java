package me.deangrant.keycloak.magiclink;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkSupportClientTest {

  @Mock private KeycloakSession session;
  @Mock private KeycloakContext keycloakContext;
  @Mock private RealmModel realm;
  @Mock private ClientModel client;
  @Mock private ClientProvider clients;
  @Mock private AuthenticationSessionModel authSession;
  @Mock private UserModel user;
  @Mock private EmailTemplateProvider email;

  @Test
  void resolveClientPrefersAuthSessionThenContext() {
    when(authSession.getClient()).thenReturn(client);
    assertEquals(client, MagicLinkSupport.resolveClient(session, authSession));

    when(authSession.getClient()).thenReturn(null);
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getClient()).thenReturn(client);
    assertEquals(client, MagicLinkSupport.resolveClient(session, authSession));

    when(keycloakContext.getClient()).thenReturn(null);
    assertNull(MagicLinkSupport.resolveClient(session, authSession));
  }

  @Test
  void resolveClientFallsBackToIssuedForLookup() {
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getClient()).thenReturn(null);
    when(authSession.getClient()).thenReturn(null);
    when(session.clients()).thenReturn(clients);
    when(clients.getClientByClientId(realm, "account")).thenReturn(client);

    assertEquals(client, MagicLinkSupport.resolveClient(session, realm, authSession, "account"));
  }

  @Test
  void clientIdAndDisplayNameAreEmptyWhenClientNull() {
    assertEquals("", MagicLinkSupport.clientId(null));
    assertEquals("", MagicLinkSupport.clientDisplayName(null));
  }

  @Test
  void sendMagicLinkEmailDoesNotThrowWhenClientNull() throws Exception {
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getRealm()).thenReturn(realm);
    when(keycloakContext.getClient()).thenReturn(null);
    when(realm.getName()).thenReturn("test");
    when(session.getProvider(EmailTemplateProvider.class)).thenReturn(email);
    when(email.setRealm(realm)).thenReturn(email);
    when(email.setUser(user)).thenReturn(email);
    when(email.setAttribute(anyString(), any())).thenReturn(email);

    assertTrue(MagicLinkSupport.sendMagicLinkEmail(session, user, "https://example/link"));

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, Object>> attrs = ArgumentCaptor.forClass(Map.class);
    verify(email)
        .send(eq("magicLinkSubject"), anyList(), eq("magic-link-email.ftl"), attrs.capture());
    assertEquals("", attrs.getValue().get("clientId"));
    assertEquals("", attrs.getValue().get("clientName"));
  }
}
