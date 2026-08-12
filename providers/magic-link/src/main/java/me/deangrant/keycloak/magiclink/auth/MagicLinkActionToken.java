package me.deangrant.keycloak.magiclink.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/** Action token carried by a standard magic-link email. */
public final class MagicLinkActionToken extends DefaultActionToken {

  /** JWT {@code typ} / action-token handler id for standard magic links. */
  public static final String TOKEN_TYPE = "magic-link";

  private static final String JSON_FIELD_REDIRECT_URI = "rdu";
  private static final String JSON_FIELD_SCOPE = "scope";
  private static final String JSON_FIELD_STATE = "state";
  private static final String JSON_FIELD_REMEMBER_ME = "rme";
  private static final String JSON_FIELD_NONCE = "nce";
  private static final String JSON_FIELD_CODE_CHALLENGE = "cc";
  private static final String JSON_FIELD_CODE_CHALLENGE_METHOD = "ccm";
  private static final String JSON_FIELD_RESPONSE_MODE = "rm";

  @JsonProperty(JSON_FIELD_REDIRECT_URI)
  private String redirectUri;

  @JsonProperty(JSON_FIELD_SCOPE)
  private String scope;

  @JsonProperty(JSON_FIELD_STATE)
  private String state;

  @JsonProperty(JSON_FIELD_REMEMBER_ME)
  private Boolean rememberMe = false;

  @JsonProperty(JSON_FIELD_NONCE)
  private String nonce;

  @JsonProperty(JSON_FIELD_CODE_CHALLENGE)
  private String codeChallenge;

  @JsonProperty(JSON_FIELD_CODE_CHALLENGE_METHOD)
  private String codeChallengeMethod;

  @JsonProperty(JSON_FIELD_RESPONSE_MODE)
  private String responseMode;

  /**
   * Creates a magic-link action token carrying OIDC redirect and PKCE session notes.
   *
   * @param userId Keycloak user id ({@code sub})
   * @param absoluteExpirationInSecs absolute expiry epoch seconds
   * @param clientId client id stored as {@code azp}
   * @param redirectUri post-login redirect URI
   * @param scope OIDC scope note; may be {@code null}
   * @param nonce OIDC nonce; may be {@code null}
   * @param state OIDC state; may be {@code null}
   * @param codeChallenge PKCE challenge; may be {@code null}
   * @param codeChallengeMethod PKCE method; may be {@code null}
   * @param rememberMe whether to set remember-me on redemption when the realm allows it
   * @param responseMode OIDC response mode; may be {@code null}
   */
  public MagicLinkActionToken(
      String userId,
      int absoluteExpirationInSecs,
      String clientId,
      String redirectUri,
      String scope,
      String nonce,
      String state,
      String codeChallenge,
      String codeChallengeMethod,
      Boolean rememberMe,
      String responseMode) {
    // Fresh action-verification nonce per mint (null → Keycloak generates a secure UUID).
    // OIDC nonce stays only in the JSON field below so re-sends are uniquely addressable.
    super(userId, TOKEN_TYPE, absoluteExpirationInSecs, null);
    this.issuedFor = clientId;
    this.redirectUri = redirectUri;
    this.scope = scope;
    this.nonce = nonce;
    this.state = state;
    this.codeChallenge = codeChallenge;
    this.codeChallengeMethod = codeChallengeMethod;
    this.rememberMe = rememberMe;
    this.responseMode = responseMode;
  }

  private MagicLinkActionToken() {
    // Required for JWT deserialization.
  }

  public String getRedirectUri() {
    return redirectUri;
  }

  public String getScope() {
    return scope;
  }

  public String getState() {
    return state;
  }

  public Boolean getRememberMe() {
    return rememberMe;
  }

  public String getNonce() {
    return nonce;
  }

  public String getCodeChallenge() {
    return codeChallenge;
  }

  public String getCodeChallengeMethod() {
    return codeChallengeMethod;
  }

  public String getResponseMode() {
    return responseMode;
  }
}
