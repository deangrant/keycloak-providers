package me.deangrant.keycloak.magiclink.spi;

import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import me.deangrant.keycloak.magiclink.auth.MagicLinkConfig;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

/** Default customization: allow all users and send the built-in magic-link email template. */
public final class DefaultMagicLinkCustomizationProvider implements MagicLinkCustomizationProvider {

  @Override
  public boolean canAuthenticate(
      AuthenticationFlowContext context, UserModel user, MagicLinkConfig config) {
    return true;
  }

  @Override
  public boolean sendMagicLinkEmail(
      KeycloakSession session, UserModel user, String link, MagicLinkConfig config) {
    return MagicLinkSupport.sendMagicLinkEmail(session, user, link);
  }

  @Override
  public void close() {}
}
