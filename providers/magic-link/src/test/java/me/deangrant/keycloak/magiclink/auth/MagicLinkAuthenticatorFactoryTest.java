package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class MagicLinkAuthenticatorFactoryTest {

  @Test
  void userSetupNotAllowed() {
    assertFalse(new MagicLinkAuthenticatorFactory().isUserSetupAllowed());
  }
}
