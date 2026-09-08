package me.deangrant.keycloak.magiclink.auth.continuation;

import org.keycloak.Config;
import org.keycloak.authentication.actiontoken.ActionTokenHandlerFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Factory for {@link MagicLinkContinuationActionTokenHandler}. */
public final class MagicLinkContinuationActionTokenHandlerFactory
    implements ActionTokenHandlerFactory<MagicLinkContinuationActionToken> {

  /** Action-token handler id; must match {@link MagicLinkContinuationActionToken#TOKEN_TYPE}. */
  public static final String PROVIDER_ID = MagicLinkContinuationActionToken.TOKEN_TYPE;

  @Override
  public MagicLinkContinuationActionTokenHandler create(KeycloakSession session) {
    return new MagicLinkContinuationActionTokenHandler();
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
