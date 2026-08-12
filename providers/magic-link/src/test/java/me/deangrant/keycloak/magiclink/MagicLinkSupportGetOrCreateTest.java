package me.deangrant.keycloak.magiclink;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MagicLinkSupportGetOrCreateTest {

  @Mock private KeycloakSession session;
  @Mock private RealmModel realm;
  @Mock private UserProvider users;
  @Mock private UserModel existing;
  @Mock private UserModel created;
  @Mock private EventBuilder event;

  @BeforeEach
  void setUp() {
    when(session.users()).thenReturn(users);
    when(realm.isLoginWithEmailAllowed()).thenReturn(true);
  }

  @Test
  void returnsExistingUserWithoutCreating() {
    when(users.getUserByEmail(realm, "alice@example.com")).thenReturn(existing);

    MagicLinkSupport.GetOrCreateResult result =
        MagicLinkSupport.getOrCreate(session, realm, "alice@example.com", true, true, true);

    assertEquals(existing, result.user());
    assertFalse(result.created());
    verify(users, never()).addUser(any(), any());
    verify(existing, never()).addRequiredAction(any(UserModel.RequiredAction.class));
  }

  @Test
  void createsUserWhenForcedAndMissingWithoutRegisterEvent() {
    when(users.getUserByEmail(realm, "new@example.com")).thenReturn(null);
    when(users.getUserByUsername(realm, "new@example.com")).thenReturn(null);
    when(users.addUser(realm, "new@example.com")).thenReturn(created);

    MagicLinkSupport.GetOrCreateResult result =
        MagicLinkSupport.getOrCreate(session, realm, "new@example.com", true, true, true);

    assertEquals(created, result.user());
    assertTrue(result.created());
    verify(created).setEnabled(true);
    verify(created).setEmail("new@example.com");
    verify(created).addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
    verify(created).addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
    verify(event, never()).success();
  }

  @Test
  void returnsNullWhenMissingAndNotForced() {
    when(users.getUserByEmail(realm, "missing@example.com")).thenReturn(null);
    when(users.getUserByUsername(realm, "missing@example.com")).thenReturn(null);

    MagicLinkSupport.GetOrCreateResult result =
        MagicLinkSupport.getOrCreate(session, realm, "missing@example.com", false, false, false);

    assertNull(result.user());
    assertFalse(result.created());
    verify(users, never()).addUser(eq(realm), any());
  }

  @Test
  void emitRegisterEventWritesSuccess() {
    when(created.getUsername()).thenReturn("new@example.com");
    when(created.getEmail()).thenReturn("new@example.com");
    when(event.event(any())).thenReturn(event);
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.user(created)).thenReturn(event);

    MagicLinkSupport.emitRegisterEvent(event, created, MagicLinkSupport.REGISTER_METHOD_MAGIC_LINK);

    verify(event).success();
  }

  @Test
  void finalizeKeepsCreatedUserAndEmitsRegister() {
    when(created.getUsername()).thenReturn("new@example.com");
    when(created.getEmail()).thenReturn("new@example.com");
    when(event.event(any())).thenReturn(event);
    when(event.detail(any(), org.mockito.ArgumentMatchers.<String>any())).thenReturn(event);
    when(event.user(created)).thenReturn(event);

    MagicLinkSupport.GetOrCreateResult result =
        new MagicLinkSupport.GetOrCreateResult(created, true);
    MagicLinkSupport.finalizeForceCreatedUser(
        session, realm, result, true, event, MagicLinkSupport.REGISTER_METHOD_MAGIC_LINK);

    verify(event).success();
    verify(users, never()).removeUser(any(), any());
  }

  @Test
  void finalizeRemovesCreatedUserWhenNotKept() {
    MagicLinkSupport.GetOrCreateResult result =
        new MagicLinkSupport.GetOrCreateResult(created, true);
    MagicLinkSupport.finalizeForceCreatedUser(
        session, realm, result, false, event, MagicLinkSupport.REGISTER_METHOD_MAGIC_LINK);

    verify(users).removeUser(realm, created);
    verify(event, never()).success();
  }

  @Test
  void finalizeIgnoresExistingUsers() {
    MagicLinkSupport.GetOrCreateResult result =
        new MagicLinkSupport.GetOrCreateResult(existing, false);
    MagicLinkSupport.finalizeForceCreatedUser(
        session, realm, result, false, event, MagicLinkSupport.REGISTER_METHOD_MAGIC_LINK);

    verify(users, never()).removeUser(any(), any());
    verify(event, never()).success();
  }

  @Test
  void trimToNullAndEmailValidation() {
    assertNull(MagicLinkSupport.trimToNull("  "));
    assertEquals("a@b.co", MagicLinkSupport.trimToNull(" a@b.co "));
    assertTrue(MagicLinkSupport.isValidEmail("user@example.com"));
  }
}
