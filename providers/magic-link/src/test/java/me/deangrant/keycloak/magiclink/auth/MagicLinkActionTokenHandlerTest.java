package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.UUID;
import me.deangrant.keycloak.magiclink.MagicLinkSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MagicLinkActionTokenHandlerTest {

  @Mock private MagicLinkActionToken token;
  @Mock private ActionTokenContext<MagicLinkActionToken> tokenContext;
  @Mock private KeycloakSession session;
  @Mock private SingleUseObjectProvider singleUse;

  @Test
  void magicLinkTokensAreSingleUse() {
    MagicLinkActionTokenHandler handler = new MagicLinkActionTokenHandler();
    assertFalse(handler.canUseTokenRepeatedly(token, tokenContext));
  }

  @Test
  void getVerifiersRejectsSupersededToken() throws Exception {
    MagicLinkActionTokenHandler handler = new MagicLinkActionTokenHandler();
    UUID latest = UUID.randomUUID();
    UUID older = UUID.randomUUID();
    when(tokenContext.getSession()).thenReturn(session);
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUse);
    when(token.getUserId()).thenReturn("user-1");
    when(token.getActionId()).thenReturn(MagicLinkActionToken.TOKEN_TYPE);
    when(token.getActionVerificationNonce()).thenReturn(older);
    when(singleUse.get(MagicLinkSupport.LATEST_MAGIC_LINK_KEY_PREFIX + "user-1"))
        .thenReturn(Map.of(MagicLinkSupport.LATEST_TOKEN_NONCE, latest.toString()));

    TokenVerifier.Predicate<? super MagicLinkActionToken>[] verifiers =
        handler.getVerifiers(tokenContext);

    assertThrows(VerificationException.class, () -> verifiers[0].test(token));
  }
}
