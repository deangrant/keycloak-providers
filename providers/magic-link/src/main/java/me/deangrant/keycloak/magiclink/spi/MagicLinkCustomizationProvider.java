package me.deangrant.keycloak.magiclink.spi;

import me.deangrant.keycloak.magiclink.auth.MagicLinkConfig;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

/**
 * Extension point for gating magic-link authentication and customizing email delivery.
 *
 * <p>Not a Keycloak {@code Spi}: instances are created by a {@link
 * MagicLinkCustomizationProviderFactory} passed into {@link
 * me.deangrant.keycloak.magiclink.auth.AbstractMagicLinkAuthenticatorFactory}, not via {@code
 * ServiceLoader}.
 *
 * <p>Implement this in a downstream Keycloak extension and wire it through a subclass of {@link
 * me.deangrant.keycloak.magiclink.auth.AbstractMagicLinkAuthenticatorFactory}.
 */
public interface MagicLinkCustomizationProvider extends Provider {

  /**
   * Returns {@code false} to abort sending a magic link.
   *
   * <p>When this method returns {@code false}, the authenticator presents the generic waiting page
   * (anti-enumeration) and does not send mail. Implementations may log or emit events, but should
   * not rely on setting their own challenge or failure for deny UX—the authenticator owns the
   * response.
   *
   * @param context current authentication flow context; never {@code null}
   * @param user resolved user about to receive a magic link; never {@code null}
   * @param config authenticator configuration for this execution; never {@code null}
   * @return {@code true} to continue sending the link
   */
  boolean canAuthenticate(
      AuthenticationFlowContext context, UserModel user, MagicLinkConfig config);

  /**
   * Sends the magic link email using the built-in template or a custom delivery path.
   *
   * @param session Keycloak session; never {@code null}
   * @param user recipient user; never {@code null}
   * @param link absolute action-token URL to include in the message; never {@code null}
   * @param config authenticator configuration for this execution; never {@code null}
   * @return {@code true} when the message was accepted for delivery
   */
  boolean sendMagicLinkEmail(
      KeycloakSession session, UserModel user, String link, MagicLinkConfig config);
}
