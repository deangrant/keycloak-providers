package me.deangrant.keycloak.magiclink.auth.continuation;

/** Auth-session note keys for the magic-link continuation flow. */
public final class ContinuationNotes {

  /** Set after the continuation email is sent; waiting page polls while this is present. */
  public static final String SESSION_INITIATED = "magic-link-continuation-initiated";

  /** Set by the continuation action-token handler when the emailed link is opened. */
  public static final String SESSION_CONFIRMED = "magic-link-continuation-confirmed";

  /** ISO-8601 expiry instant for the original device's waiting session. */
  public static final String SESSION_EXPIRATION = "magic-link-continuation-expiration";

  private ContinuationNotes() {}
}
