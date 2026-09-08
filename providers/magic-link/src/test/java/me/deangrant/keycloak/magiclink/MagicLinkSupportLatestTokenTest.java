package me.deangrant.keycloak.magiclink;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.UUID;
import me.deangrant.keycloak.magiclink.auth.MagicLinkActionToken;
import me.deangrant.keycloak.magiclink.auth.continuation.MagicLinkContinuationActionToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MagicLinkSupportLatestTokenTest {

  @Mock private KeycloakSession session;
  @Mock private SingleUseObjectProvider singleUse;
  @Mock private MagicLinkActionToken magicLinkToken;
  @Mock private MagicLinkContinuationActionToken continuationToken;

  @Test
  void acceptsWhenNoLatestPointerExists() {
    when(magicLinkToken.getUserId()).thenReturn("user-1");
    when(magicLinkToken.getActionId()).thenReturn(MagicLinkActionToken.TOKEN_TYPE);
    when(magicLinkToken.getActionVerificationNonce()).thenReturn(UUID.randomUUID());
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUse);
    when(singleUse.get(MagicLinkSupport.LATEST_MAGIC_LINK_KEY_PREFIX + "user-1")).thenReturn(null);

    assertTrue(MagicLinkSupport.isLatestActionToken(session, magicLinkToken));
  }

  @Test
  void rememberThenOnlyMatchingNonceIsLatest() {
    UUID latest = UUID.randomUUID();
    UUID older = UUID.randomUUID();
    when(magicLinkToken.getUserId()).thenReturn("user-1");
    when(magicLinkToken.getActionId()).thenReturn(MagicLinkActionToken.TOKEN_TYPE);
    when(magicLinkToken.getActionVerificationNonce()).thenReturn(latest);
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUse);

    MagicLinkSupport.rememberLatestActionToken(session, magicLinkToken, 900);

    @SuppressWarnings("unchecked")
    ArgumentCaptor<Map<String, String>> notes = ArgumentCaptor.forClass(Map.class);
    verify(singleUse)
        .put(
            eq(MagicLinkSupport.LATEST_MAGIC_LINK_KEY_PREFIX + "user-1"),
            eq(900L),
            notes.capture());
    assertTrue(latest.toString().equals(notes.getValue().get(MagicLinkSupport.LATEST_TOKEN_NONCE)));

    when(singleUse.get(MagicLinkSupport.LATEST_MAGIC_LINK_KEY_PREFIX + "user-1"))
        .thenReturn(Map.of(MagicLinkSupport.LATEST_TOKEN_NONCE, latest.toString()));
    assertTrue(MagicLinkSupport.isLatestActionToken(session, magicLinkToken));

    when(magicLinkToken.getActionVerificationNonce()).thenReturn(older);
    assertFalse(MagicLinkSupport.isLatestActionToken(session, magicLinkToken));
  }

  @Test
  void newRememberSupersedesPreviousNonce() {
    UUID first = UUID.randomUUID();
    UUID second = UUID.randomUUID();
    when(continuationToken.getUserId()).thenReturn("user-2");
    when(continuationToken.getActionId()).thenReturn(MagicLinkContinuationActionToken.TOKEN_TYPE);
    when(continuationToken.getActionVerificationNonce()).thenReturn(first, second);
    when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUse);

    MagicLinkSupport.rememberLatestActionToken(session, continuationToken, 600);
    MagicLinkSupport.rememberLatestActionToken(session, continuationToken, 600);

    when(singleUse.get(MagicLinkSupport.LATEST_CONTINUATION_KEY_PREFIX + "user-2"))
        .thenReturn(Map.of(MagicLinkSupport.LATEST_TOKEN_NONCE, second.toString()));
    when(continuationToken.getActionVerificationNonce()).thenReturn(second);
    assertTrue(MagicLinkSupport.isLatestActionToken(session, continuationToken));
    when(continuationToken.getActionVerificationNonce()).thenReturn(first);
    assertFalse(MagicLinkSupport.isLatestActionToken(session, continuationToken));
  }
}
