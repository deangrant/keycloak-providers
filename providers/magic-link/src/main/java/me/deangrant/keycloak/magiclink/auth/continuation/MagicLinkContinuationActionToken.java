package me.deangrant.keycloak.magiclink.auth.continuation;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/** Action token that confirms a pending magic-link continuation on the original device. */
public final class MagicLinkContinuationActionToken extends DefaultActionToken {

  /** JWT {@code typ} / action-token handler id for continuation confirmations. */
  public static final String TOKEN_TYPE = "magic-link-continuation";

  private static final String JSON_FIELD_SESSION_ID = "sid";
  private static final String JSON_FIELD_TAB_ID = "tid";
  private static final String JSON_FIELD_REDIRECT_URI = "rdu";

  @JsonProperty(JSON_FIELD_SESSION_ID)
  private String sessionId;

  @JsonProperty(JSON_FIELD_TAB_ID)
  private String tabId;

  @JsonProperty(JSON_FIELD_REDIRECT_URI)
  private String redirectUri;

  /**
   * Creates a continuation token that points back to the original authentication session.
   *
   * @param userId Keycloak user id ({@code sub})
   * @param absoluteExpirationInSecs absolute expiry epoch seconds
   * @param clientId client id stored as {@code azp}
   * @param nonce OIDC nonce; may be {@code null}
   * @param sessionId root authentication session id to confirm
   * @param tabId authentication tab id within the root session
   * @param redirectUri original redirect URI shown on the confirmation page
   */
  public MagicLinkContinuationActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String nonce,
      String sessionId,
      String tabId,
      String redirectUri) {
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, parseNonce(nonce));
    this.issuedFor = clientId;
    this.sessionId = sessionId;
    this.tabId = tabId;
    this.redirectUri = redirectUri;
  }

  private MagicLinkContinuationActionToken() {
    // Required for JWT deserialization.
  }

  private static UUID parseNonce(String nonce) {
    if (nonce == null) {
      return null;
    }
    try {
      return UUID.fromString(nonce);
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  public String getSessionId() {
    return sessionId;
  }

  public String getTabId() {
    return tabId;
  }

  public String getRedirectUri() {
    return redirectUri;
  }
}
