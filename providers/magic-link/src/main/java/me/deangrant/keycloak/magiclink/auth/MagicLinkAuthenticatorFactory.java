package me.deangrant.keycloak.magiclink.auth;

import me.deangrant.keycloak.magiclink.spi.DefaultMagicLinkCustomizationProviderFactory;

/** Default magic-link authenticator factory registered with Keycloak. */
public final class MagicLinkAuthenticatorFactory extends AbstractMagicLinkAuthenticatorFactory {

  /** Keycloak authenticator provider id: {@code magic-link}. */
  public static final String PROVIDER_ID = "magic-link";

  /** Creates the default factory wired to {@link DefaultMagicLinkCustomizationProviderFactory}. */
  public MagicLinkAuthenticatorFactory() {
    super(new DefaultMagicLinkCustomizationProviderFactory());
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "Magic Link";
  }

  @Override
  public String getHelpText() {
    return "Authenticate by sending a one-time magic link to the user's email.";
  }
}
