package me.deangrant.keycloak.magiclink.spi;

import java.util.Map;
import org.keycloak.models.KeycloakSession;

/** Factory for {@link DefaultMagicLinkCustomizationProvider}. */
public final class DefaultMagicLinkCustomizationProviderFactory
    implements MagicLinkCustomizationProviderFactory {

  @Override
  public MagicLinkCustomizationProvider create(
      KeycloakSession session, Map<String, String> authenticatorConfig) {
    return new DefaultMagicLinkCustomizationProvider();
  }
}
