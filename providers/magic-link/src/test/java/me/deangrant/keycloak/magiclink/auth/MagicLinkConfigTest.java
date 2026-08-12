package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

class MagicLinkConfigTest {

  @Test
  void defaultsWhenConfigMissing() {
    MagicLinkConfig config = new MagicLinkConfig((AuthenticatorConfigModel) null);
    assertFalse(config.isForceCreate());
    assertFalse(config.isUpdateProfile());
    assertFalse(config.isUpdatePassword());
    assertEquals(
        OptionalInt.of(MagicLinkConfig.DEFAULT_TOKEN_LIFESPAN_SECONDS), config.getTokenLifespan());
  }

  @Test
  void parsesFlagsAndLifespan() {
    MagicLinkConfig config =
        new MagicLinkConfig(
            Map.of(
                MagicLinkConfig.FORCE_CREATE, "true",
                MagicLinkConfig.UPDATE_PROFILE, "true",
                MagicLinkConfig.UPDATE_PASSWORD, "true",
                MagicLinkConfig.TOKEN_LIFESPAN_SECONDS, "120"));
    assertTrue(config.isForceCreate());
    assertTrue(config.isUpdateProfile());
    assertTrue(config.isUpdatePassword());
    assertEquals(OptionalInt.of(120), config.getTokenLifespan());
  }

  @Test
  void invalidLifespanFallsBackToDefault() {
    MagicLinkConfig config =
        new MagicLinkConfig(Map.of(MagicLinkConfig.TOKEN_LIFESPAN_SECONDS, "nope"));
    assertEquals(
        OptionalInt.of(MagicLinkConfig.DEFAULT_TOKEN_LIFESPAN_SECONDS), config.getTokenLifespan());
  }
}
