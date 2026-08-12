package me.deangrant.keycloak.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ServiceLoader;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.UserModel;

class LastLoginTimestampListenerFactoryTest {

  @Test
  void defaultAndValidCustomNamesAreAccepted() {
    assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("lastLoginTimestamp"));
    assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("customAttr"));
    assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("attr_1"));
    assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("A"));
    assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("a".repeat(64)));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        UserModel.ID,
        UserModel.USERNAME,
        UserModel.EMAIL,
        UserModel.FIRST_NAME,
        UserModel.LAST_NAME,
        UserModel.EMAIL_VERIFIED,
        UserModel.ENABLED,
        UserModel.LOCALE,
        UserModel.CREATED_TIMESTAMP,
        UserModel.DISABLED_REASON,
        UserModel.DID,
        UserModel.IS_TEMP_ADMIN_ATTR_NAME
      })
  void reservedNamesAreRejected(String reserved) {
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(reserved));
  }

  @Test
  void illegalPatternsAreRejected() {
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("1abc"));
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("bad-name"));
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("has space"));
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("has.dot"));
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("a".repeat(65)));
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("_leading"));
    assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("weird!"));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"  ", "\t"})
  void initFallsBackToDefaultForBlankConfig(String configured) {
    LastLoginTimestampListenerFactory factory = new LastLoginTimestampListenerFactory();
    Config.Scope scope = mock(Config.Scope.class);
    when(scope.get("attribute-name")).thenReturn(configured);
    factory.init(scope);
    try {
      assertEquals("lastLoginTimestamp", factory.resolvedAttributeName());
    } finally {
      factory.close();
    }
  }

  @Test
  void initKeepsValidCustomAttributeName() {
    LastLoginTimestampListenerFactory factory = new LastLoginTimestampListenerFactory();
    Config.Scope scope = mock(Config.Scope.class);
    when(scope.get("attribute-name")).thenReturn("  myLastLogin  ");
    factory.init(scope);
    try {
      assertEquals("myLastLogin", factory.resolvedAttributeName());
    } finally {
      factory.close();
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {UserModel.USERNAME, "1bad", "bad-name"})
  void initFallsBackToDefaultForInvalidConfig(String configured) {
    // Invalid configured names fall back via resolveAttributeName / init;
    // WARN is emitted by init but not asserted here (no log capture).
    LastLoginTimestampListenerFactory factory = new LastLoginTimestampListenerFactory();
    Config.Scope scope = mock(Config.Scope.class);
    when(scope.get("attribute-name")).thenReturn(configured);
    factory.init(scope);
    try {
      assertEquals("lastLoginTimestamp", factory.resolvedAttributeName());
    } finally {
      factory.close();
    }
  }

  @Test
  void serviceLoaderFindsFactoryAndGetIdMatchesProviderId() {
    EventListenerProviderFactory loaded =
        StreamSupport.stream(
                ServiceLoader.load(EventListenerProviderFactory.class).spliterator(), false)
            .filter(f -> f instanceof LastLoginTimestampListenerFactory)
            .findFirst()
            .orElseThrow(
                () -> new AssertionError("LastLoginTimestampListenerFactory not on ServiceLoader"));
    assertInstanceOf(LastLoginTimestampListenerFactory.class, loaded);
    assertEquals(LastLoginTimestampListenerFactory.PROVIDER_ID, loaded.getId());
    assertEquals("last-login-timestamp", loaded.getId());
  }
}
