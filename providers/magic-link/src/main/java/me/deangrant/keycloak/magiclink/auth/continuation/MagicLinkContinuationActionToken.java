package me.deangrant.keycloak.magiclink.auth.continuation;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/** Action token that confirms a pending magic-link continuation on the original device. */
public final class MagicLinkContinuationActionToken extends DefaultActionToken {

  /** JWT {@code typ} / action-token handler id for continuation confirmations. */
  public static final String TOKEN_TYPE = "magic-link-continuation";

  private static final String JSON_FIELD_SESSION_ID = "sid";
  private static final String JSON_FIELD_TAB_ID = "tid";

  @JsonProperty(JSON_FIELD_SESSION_ID)
  private String sessionId;

  @JsonProperty(JSON_FIELD_TAB_ID)
  private String tabId;

  /**
   * Creates a continuation token that points back to the original authentication session.
   *
   * @param userId Keycloak user id ({@code sub})
   * @param absoluteExpirationInSecs absolute expiry epoch seconds
   * @param clientId client id stored as {@code azp}
   * @param sessionId root authentication session id to confirm
   * @param tabId authentication tab id within the root session
   */
  public MagicLinkContinuationActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String sessionId,
      String tabId) {
    // Fresh action-verification nonce per mint (null → Keycloak generates a secure UUID).
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null);
    this.issuedFor = clientId;
    this.sessionId = sessionId;
    this.tabId = tabId;
  }

  private MagicLinkContinuationActionToken() {
    // Required for JWT deserialization.
  }

  public String getSessionId() {
    return sessionId;
  }

  public String getTabId() {
    return tabId;
  }
}
