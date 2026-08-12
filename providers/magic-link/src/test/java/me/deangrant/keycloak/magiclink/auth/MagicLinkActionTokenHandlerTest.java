package me.deangrant.keycloak.magiclink.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MagicLinkActionTokenHandlerTest {

  @Mock private MagicLinkActionToken token;
  @Mock private ActionTokenContext<MagicLinkActionToken> tokenContext;

  @Test
  void magicLinkTokensAreSingleUse() {
    MagicLinkActionTokenHandler handler = new MagicLinkActionTokenHandler();
    assertFalse(handler.canUseTokenRepeatedly(token, tokenContext));
  }
}
