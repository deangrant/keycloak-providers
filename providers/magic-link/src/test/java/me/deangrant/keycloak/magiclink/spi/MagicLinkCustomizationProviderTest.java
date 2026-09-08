package me.deangrant.keycloak.magiclink.spi;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

import jakarta.ws.rs.core.Response;
import java.util.Map;
import me.deangrant.keycloak.magiclink.auth.AbstractMagicLinkAuthenticatorFactory;
import me.deangrant.keycloak.magiclink.auth.MagicLinkConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MagicLinkCustomizationProviderTest {

  @Mock private AuthenticationFlowContext context;
  @Mock private UserModel user;
  @Mock private KeycloakSession session;
  @Mock private Response deny;

  @Test
  void defaultProviderAllowsAllUsers() {
    DefaultMagicLinkCustomizationProvider provider = new DefaultMagicLinkCustomizationProvider();
    assertTrue(provider.canAuthenticate(context, user, new MagicLinkConfig(Map.of())));
  }

  @Test
  void customProviderCanDeny() {
    MagicLinkCustomizationProvider provider =
        new MagicLinkCustomizationProvider() {
          @Override
          public boolean canAuthenticate(
              AuthenticationFlowContext context, UserModel user, MagicLinkConfig config) {
            context.failure(AuthenticationFlowError.ACCESS_DENIED, deny);
            return false;
          }

          @Override
          public boolean sendMagicLinkEmail(
              KeycloakSession session, UserModel user, String link, MagicLinkConfig config) {
            return false;
          }

          @Override
          public void close() {}
        };

    assertFalse(provider.canAuthenticate(context, user, new MagicLinkConfig(Map.of())));
    verify(context).failure(AuthenticationFlowError.ACCESS_DENIED, deny);
  }

  @Test
  void abstractFactoryWiresCustomizationFactory() {
    MagicLinkCustomizationProviderFactory factory =
        (session, config) -> new DefaultMagicLinkCustomizationProvider();
    AbstractMagicLinkAuthenticatorFactory authenticatorFactory =
        new AbstractMagicLinkAuthenticatorFactory(factory) {
          @Override
          public String getId() {
            return "magic-link-test";
          }

          @Override
          public String getDisplayType() {
            return "Magic Link Test";
          }

          @Override
          public String getHelpText() {
            return "test";
          }
        };

    Authenticator authenticator = authenticatorFactory.create(session);
    assertTrue(
        authenticator instanceof me.deangrant.keycloak.magiclink.auth.MagicLinkAuthenticator);
  }
}
