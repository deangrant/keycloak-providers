package me.deangrant.keycloak.magiclink.spi;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Creates {@link MagicLinkCustomizationProvider} instances and optionally contributes extra admin
 * UI config properties for a magic-link authenticator variant.
 */
public interface MagicLinkCustomizationProviderFactory {

  /**
   * Creates a customization provider for the current authentication attempt.
   *
   * @param session Keycloak session; never {@code null}
   * @param authenticatorConfig per-execution authenticator config map; never {@code null}, may be
   *     empty
   * @return provider used to gate authentication and send email; never {@code null}
   */
  MagicLinkCustomizationProvider create(
      KeycloakSession session, Map<String, String> authenticatorConfig);

  /**
   * Returns extra admin-UI config properties appended after the built-in magic-link settings.
   *
   * @return additional properties; never {@code null} (defaults to an empty list)
   */
  default List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }
}
