package me.deangrant.keycloak.magiclink.auth;

import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Factory for {@link MagicLinkActionTokenHandler}. */
public final class MagicLinkActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<MagicLinkActionToken> {

  /** Action-token handler id; must match {@link MagicLinkActionToken#TOKEN_TYPE}. */
  public static final String PROVIDER_ID = MagicLinkActionToken.TOKEN_TYPE;

  @Override
  public MagicLinkActionTokenHandler create(KeycloakSession session) {
    return new MagicLinkActionTokenHandler();
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
