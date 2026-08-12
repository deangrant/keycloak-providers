package me.deangrant.keycloak.magiclink;

import jakarta.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import me.deangrant.keycloak.magiclink.auth.MagicLinkActionToken;
import me.deangrant.keycloak.magiclink.auth.continuation.MagicLinkContinuationActionToken;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;

/** Shared helpers for magic link and email OTP authenticators. */
public final class MagicLinkSupport {

  private static final Logger LOG = Logger.getLogger(MagicLinkSupport.class);

  /** {@code Details.REGISTER_METHOD} value when a user is created via magic link. */
  public static final String REGISTER_METHOD_MAGIC_LINK = "magic-link";

  private MagicLinkSupport() {}

  /** Returns {@code null} when {@code value} is {@code null} or blank after trim. */
  public static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  public static boolean isValidEmail(String email) {
    return email != null && Validation.isEmailValid(email);
  }

  /**
   * Resolves the email or username already established in the current authentication attempt.
   *
   * @param context authentication flow context; never {@code null}
   * @return attempted identity, or {@code null} if none is available yet
   */
  public static String getAttemptedUsername(AuthenticationFlowContext context) {
    if (context.getUser() != null && context.getUser().getEmail() != null) {
      return context.getUser().getEmail();
    }
    String username =
        trimToNull(
            context
                .getAuthenticationSession()
                .getAuthNote(
                    org.keycloak.authentication.authenticators.browser
                        .AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME));
    if (username == null) {
      return null;
    }
    if (isValidEmail(username)) {
      return username;
    }
    UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
    if (user != null && user.getEmail() != null) {
      return user.getEmail();
    }
    return username;
  }

  /**
   * Looks up a user by email/username and optionally creates one when missing.
   *
   * <p>Does not emit a {@code REGISTER} event; callers must call {@link #finalizeForceCreatedUser}
   * after a successful email send (or remove the user on failure).
   *
   * @param session Keycloak session; never {@code null}
   * @param realm realm to search; never {@code null}
   * @param emailOrUsername submitted identity; blank yields a null user result
   * @param forceCreate when {@code true}, creates an enabled user if none exists
   * @param updateProfile when creating, adds {@code UPDATE_PROFILE}
   * @param updatePassword when creating, adds {@code UPDATE_PASSWORD}
   * @return result with the user (or {@code null}) and whether that user was newly created
   */
  public static GetOrCreateResult getOrCreate(
      KeycloakSession session,
      RealmModel realm,
      String emailOrUsername,
      boolean forceCreate,
      boolean updateProfile,
      boolean updatePassword) {
    String identity = trimToNull(emailOrUsername);
    if (identity == null) {
      return new GetOrCreateResult(null, false);
    }

    UserModel user = KeycloakModelUtils.findUserByNameOrEmail(session, realm, identity);
    if (user != null) {
      return new GetOrCreateResult(user, false);
    }
    if (!forceCreate || !isValidEmail(identity)) {
      return new GetOrCreateResult(null, false);
    }

    user = session.users().addUser(realm, identity);
    user.setEnabled(true);
    user.setEmail(identity);
    if (updatePassword) {
      user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
    }
    if (updateProfile) {
      user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);
    }
    return new GetOrCreateResult(user, true);
  }

  /**
   * Outcome of {@link #getOrCreate}: the resolved user and whether it was created in this call.
   *
   * @param user existing or newly created user, or {@code null} when missing and create is disabled
   * @param created {@code true} when {@code user} was created by this call
   */
  public record GetOrCreateResult(UserModel user, boolean created) {}

  /**
   * Emits a successful {@code REGISTER} event for a user created via magic-link force-create.
   *
   * @param event event builder; ignored when {@code null}
   * @param user newly created user; never {@code null}
   * @param registerMethod value for {@code Details.REGISTER_METHOD}
   */
  public static void emitRegisterEvent(EventBuilder event, UserModel user, String registerMethod) {
    if (event == null || user == null) {
      return;
    }
    event
        .event(EventType.REGISTER)
        .detail(Details.REGISTER_METHOD, registerMethod)
        .detail(Details.USERNAME, user.getUsername())
        .detail(Details.EMAIL, user.getEmail())
        .user(user)
        .success();
  }

  /**
   * Removes a user created for force-create that should not be retained.
   *
   * @param session Keycloak session; never {@code null}
   * @param realm realm owning the user; never {@code null}
   * @param user user to remove; ignored when {@code null}
   */
  public static void removeUser(KeycloakSession session, RealmModel realm, UserModel user) {
    if (user == null) {
      return;
    }
    try {
      session.users().removeUser(realm, user);
    } catch (RuntimeException e) {
      LOG.warnf(e, "Failed to roll back force-created user %s", user.getId());
    }
  }

  /**
   * After an email send attempt for a force-created user, emit {@code REGISTER} on success or
   * remove the orphan on failure. Existing users are left unchanged.
   *
   * @param session Keycloak session; never {@code null}
   * @param realm realm; never {@code null}
   * @param result outcome from {@link #getOrCreate}
   * @param keep {@code true} when the email was sent (or the user should otherwise be retained)
   * @param event optional builder for {@code REGISTER}; may be {@code null}
   * @param registerMethod value for {@code Details.REGISTER_METHOD} when emitting
   */
  public static void finalizeForceCreatedUser(
      KeycloakSession session,
      RealmModel realm,
      GetOrCreateResult result,
      boolean keep,
      EventBuilder event,
      String registerMethod) {
    if (result == null || !result.created() || result.user() == null) {
      return;
    }
    if (keep) {
      emitRegisterEvent(event, result.user(), registerMethod);
    } else {
      removeUser(session, realm, result.user());
    }
  }

  /**
   * Builds a signed magic-link action token from the current authentication session notes.
   *
   * @param user authenticated recipient; never {@code null}
   * @param clientId OIDC client id encoded as {@code azp}; never {@code null}
   * @param validitySeconds token TTL; empty uses 15 minutes
   * @param rememberMe whether to honor realm remember-me on redemption
   * @param authSession current authentication session supplying redirect/OIDC notes; never {@code
   *     null}
   * @return new action token ready to serialize
   */
  public static MagicLinkActionToken createMagicLinkToken(
      UserModel user,
      String clientId,
      OptionalInt validitySeconds,
      boolean rememberMe,
      AuthenticationSessionModel authSession) {
    int validity = validitySeconds.orElse(15 * 60);
    int absoluteExpiration = Time.currentTime() + validity;
    return new MagicLinkActionToken(
        user.getId(),
        absoluteExpiration,
        clientId,
        authSession.getRedirectUri(),
        authSession.getClientNote(OIDCLoginProtocol.SCOPE_PARAM),
        authSession.getClientNote(OIDCLoginProtocol.NONCE_PARAM),
        authSession.getClientNote(OIDCLoginProtocol.STATE_PARAM),
        authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_PARAM),
        authSession.getClientNote(OIDCLoginProtocol.CODE_CHALLENGE_METHOD_PARAM),
        rememberMe,
        authSession.getClientNote(OIDCLoginProtocol.RESPONSE_MODE_PARAM));
  }

  /**
   * Builds a continuation action token that identifies the original root session and tab.
   *
   * @param user user awaiting confirmation; never {@code null}
   * @param clientId OIDC client id; never {@code null}
   * @param validitySeconds token TTL in seconds
   * @param authSession original-device authentication session; never {@code null}
   * @return new continuation action token ready to serialize
   */
  public static MagicLinkContinuationActionToken createContinuationToken(
      UserModel user,
      String clientId,
      int validitySeconds,
      AuthenticationSessionModel authSession) {
    int absoluteExpiration = Time.currentTime() + validitySeconds;
    return new MagicLinkContinuationActionToken(
        user.getId(),
        absoluteExpiration,
        clientId,
        authSession.getParentSession().getId(),
        authSession.getTabId());
  }

  /** Map key stored under the latest-token SingleUseObject entry. */
  public static final String LATEST_TOKEN_NONCE = "nonce";

  /**
   * SingleUseObject key prefix for the latest successfully emailed standard magic-link token for a
   * user.
   */
  public static final String LATEST_MAGIC_LINK_KEY_PREFIX = "magic-link.latest.";

  /**
   * SingleUseObject key prefix for the latest successfully emailed continuation token for a user.
   */
  public static final String LATEST_CONTINUATION_KEY_PREFIX = "magic-link-continuation.latest.";

  /**
   * Records {@code token}'s action-verification nonce as the only redeemable outstanding token for
   * this user and token type. Call only after a successful email send.
   *
   * @param session Keycloak session; never {@code null}
   * @param token minted action token; never {@code null}
   * @param lifespanSeconds TTL for the latest-pointer entry (token lifespan)
   */
  public static void rememberLatestActionToken(
      KeycloakSession session,
      org.keycloak.authentication.actiontoken.DefaultActionToken token,
      int lifespanSeconds) {
    if (session == null || token == null || token.getUserId() == null) {
      return;
    }
    if (token.getActionVerificationNonce() == null || lifespanSeconds <= 0) {
      return;
    }
    SingleUseObjectProvider singleUse = session.getProvider(SingleUseObjectProvider.class);
    if (singleUse == null) {
      return;
    }
    String key = latestTokenKey(token.getActionId(), token.getUserId());
    if (key == null) {
      return;
    }
    singleUse.put(
        key,
        lifespanSeconds,
        Map.of(LATEST_TOKEN_NONCE, token.getActionVerificationNonce().toString()));
  }

  /**
   * Returns whether {@code token} is still the latest successfully emailed token for its user, or
   * whether no latest pointer exists yet (pre-upgrade outstanding mail).
   *
   * @param session Keycloak session; never {@code null}
   * @param token presented action token; never {@code null}
   * @return {@code true} when the token may be redeemed under the latest-token policy
   */
  public static boolean isLatestActionToken(
      KeycloakSession session, org.keycloak.authentication.actiontoken.DefaultActionToken token) {
    if (session == null || token == null || token.getUserId() == null) {
      return false;
    }
    if (token.getActionVerificationNonce() == null) {
      return false;
    }
    SingleUseObjectProvider singleUse = session.getProvider(SingleUseObjectProvider.class);
    if (singleUse == null) {
      // Fail open only when the provider is unavailable; prefer not to brick logins.
      return true;
    }
    String key = latestTokenKey(token.getActionId(), token.getUserId());
    if (key == null) {
      return false;
    }
    Map<String, String> latest = singleUse.get(key);
    if (latest == null) {
      // No successful send recorded yet under this policy (legacy outstanding mail).
      return true;
    }
    return token.getActionVerificationNonce().toString().equals(latest.get(LATEST_TOKEN_NONCE));
  }

  static String latestTokenKey(String tokenType, String userId) {
    if (userId == null) {
      return null;
    }
    if (MagicLinkActionToken.TOKEN_TYPE.equals(tokenType)) {
      return LATEST_MAGIC_LINK_KEY_PREFIX + userId;
    }
    if (MagicLinkContinuationActionToken.TOKEN_TYPE.equals(tokenType)) {
      return LATEST_CONTINUATION_KEY_PREFIX + userId;
    }
    return null;
  }

  /**
   * Serializes {@code token} into a realm login-actions action-token URL.
   *
   * @param session Keycloak session used for signing; never {@code null}
   * @param realm realm whose keys sign the token; never {@code null}
   * @param token action token to serialize; never {@code null}
   * @return absolute URL including {@code key} and {@code client_id} query params
   */
  public static String linkFromActionToken(
      KeycloakSession session,
      RealmModel realm,
      org.keycloak.authentication.actiontoken.DefaultActionToken token) {
    UriInfo uriInfo = session.getContext().getUri();
    RealmModel previous = session.getContext().getRealm();
    session.getContext().setRealm(realm);
    try {
      String serialized = token.serialize(session, realm, uriInfo);
      return Urls.realmBase(uriInfo.getBaseUri())
          .path(RealmsResource.class, "getLoginActionsService")
          .path(LoginActionsService.class, "executeActionToken")
          .queryParam(Constants.KEY, serialized)
          .queryParam(Constants.CLIENT_ID, token.getIssuedFor())
          .build(realm.getName())
          .toString();
    } finally {
      session.getContext().setRealm(previous);
    }
  }

  /**
   * Sends the standard magic-link email template to {@code user}.
   *
   * @return {@code true} if Keycloak accepted the message for delivery
   */
  public static boolean sendMagicLinkEmail(KeycloakSession session, UserModel user, String link) {
    ClientModel client = resolveClient(session, null);
    Map<String, Object> attrs = new HashMap<>();
    attrs.put("magicLink", link);
    attrs.put("realmName", realmDisplayName(session.getContext().getRealm()));
    attrs.put("clientName", clientDisplayName(client));
    attrs.put("clientId", clientId(client));
    return sendTemplatedEmail(session, user, "magicLinkSubject", "magic-link-email.ftl", attrs);
  }

  /**
   * Sends the magic-link continuation email template to {@code user}.
   *
   * @return {@code true} if Keycloak accepted the message for delivery
   */
  public static boolean sendContinuationEmail(
      KeycloakSession session, UserModel user, String link) {
    ClientModel client = resolveClient(session, null);
    Map<String, Object> attrs = new HashMap<>();
    attrs.put("magicLink", link);
    attrs.put("realmName", realmDisplayName(session.getContext().getRealm()));
    attrs.put("clientName", clientDisplayName(client));
    attrs.put("clientId", clientId(client));
    return sendTemplatedEmail(
        session, user, "magicLinkContinuationSubject", "magic-link-continuation-email.ftl", attrs);
  }

  /**
   * Sends the email-OTP template containing {@code code}.
   *
   * @return {@code true} if Keycloak accepted the message for delivery
   */
  public static boolean sendOtpEmail(KeycloakSession session, UserModel user, String code) {
    ClientModel client = resolveClient(session, null);
    Map<String, Object> attrs = new HashMap<>();
    attrs.put("code", code);
    attrs.put("realmName", realmDisplayName(session.getContext().getRealm()));
    attrs.put("clientName", clientDisplayName(client));
    return sendTemplatedEmail(session, user, "otpSubject", "email-otp.ftl", attrs);
  }

  private static boolean sendTemplatedEmail(
      KeycloakSession session,
      UserModel user,
      String subjectKey,
      String template,
      Map<String, Object> bodyAttributes) {
    RealmModel realm = session.getContext().getRealm();
    ClientModel client = resolveClient(session, null);
    try {
      EmailTemplateProvider email = session.getProvider(EmailTemplateProvider.class);
      String realmName = realmDisplayName(realm);
      String clientName = clientDisplayName(client);
      email
          .setRealm(realm)
          .setUser(user)
          .setAttribute("realmName", realmName)
          .setAttribute("clientName", clientName)
          .send(subjectKey, List.of(realmName, clientName), template, bodyAttributes);
      return true;
    } catch (EmailException e) {
      LOG.errorf(e, "Failed to send email template %s", template);
      return false;
    }
  }

  /**
   * Resolves the active client from the authentication session, falling back to the Keycloak
   * context client.
   *
   * @param session Keycloak session; never {@code null}
   * @param authSession current authentication session; may be {@code null}
   * @return resolved client, or {@code null} when neither source has one
   */
  public static ClientModel resolveClient(
      KeycloakSession session, AuthenticationSessionModel authSession) {
    if (authSession != null && authSession.getClient() != null) {
      return authSession.getClient();
    }
    if (session != null && session.getContext() != null) {
      return session.getContext().getClient();
    }
    return null;
  }

  /**
   * Resolves a client for action-token handling: auth session, then context, then lookup by {@code
   * issuedFor}.
   *
   * @param session Keycloak session; never {@code null}
   * @param realm realm used for client lookup; never {@code null}
   * @param authSession current authentication session; may be {@code null}
   * @param issuedFor client id from the action token ({@code azp}); may be {@code null}
   * @return resolved client, or {@code null} when none can be found
   */
  public static ClientModel resolveClient(
      KeycloakSession session,
      RealmModel realm,
      AuthenticationSessionModel authSession,
      String issuedFor) {
    ClientModel client = resolveClient(session, authSession);
    if (client != null) {
      return client;
    }
    if (session == null || realm == null || issuedFor == null || issuedFor.isBlank()) {
      return null;
    }
    return session.clients().getClientByClientId(realm, issuedFor);
  }

  /**
   * Returns the client id, or an empty string when {@code client} is {@code null}.
   *
   * @param client client model; may be {@code null}
   * @return non-null client id string suitable for templates
   */
  public static String clientId(ClientModel client) {
    if (client == null || client.getClientId() == null) {
      return "";
    }
    return client.getClientId();
  }

  public static String realmDisplayName(RealmModel realm) {
    if (realm.getDisplayName() != null && !realm.getDisplayName().isBlank()) {
      return realm.getDisplayName();
    }
    return realm.getName();
  }

  public static String clientDisplayName(ClientModel client) {
    if (client == null) {
      return "";
    }
    if (client.getName() != null && !client.getName().isBlank()) {
      return client.getName();
    }
    return clientId(client);
  }
}
