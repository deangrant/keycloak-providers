package me.deangrant.keycloak.magiclink.auth;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import me.deangrant.keycloak.magiclink.spi.MagicLinkCustomizationProviderFactory;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Base factory for magic-link authenticator variants.
 *
 * <p>Subclass this in another Keycloak project, pass a custom {@link
 * MagicLinkCustomizationProviderFactory}, and register a unique provider id.
 */
public abstract class AbstractMagicLinkAuthenticatorFactory implements AuthenticatorFactory {

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
    AuthenticationExecutionModel.Requirement.REQUIRED,
    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
    AuthenticationExecutionModel.Requirement.DISABLED
  };

  private final MagicLinkCustomizationProviderFactory customizationProviderFactory;

  /**
   * Creates a factory wired to the given customization factory (constructor injection, not Keycloak
   * SPI discovery).
   *
   * @param customizationProviderFactory factory used at authentication time; never {@code null}
   */
  protected AbstractMagicLinkAuthenticatorFactory(
      MagicLinkCustomizationProviderFactory customizationProviderFactory) {
    this.customizationProviderFactory = customizationProviderFactory;
  }

  @Override
  public final boolean isConfigurable() {
    return true;
  }

  @Override
  public final boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public final AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public final String getReferenceCategory() {
    return "alternate-auth";
  }

  /**
   * Returns built-in {@link MagicLinkConfig} properties followed by any customization properties.
   */
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Stream.concat(
            MagicLinkConfig.CONFIG_PROPERTIES.stream(),
            customizationProviderFactory.getConfigProperties().stream())
        .collect(Collectors.toList());
  }

  /** Creates a {@link MagicLinkAuthenticator} bound to this factory's customization provider. */
  @Override
  public Authenticator create(KeycloakSession session) {
    return new MagicLinkAuthenticator(customizationProviderFactory);
  }

  @Override
  public final void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public final void close() {}
}
