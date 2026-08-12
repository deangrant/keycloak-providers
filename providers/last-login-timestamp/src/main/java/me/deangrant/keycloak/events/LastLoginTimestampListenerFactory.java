package me.deangrant.keycloak.events;

import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

/**
 * Factory for the last-login-timestamp {@link EventListenerProviderFactory} SPI.
 *
 * <p>Enable this listener on a realm via Realm Settings > Events > Event listeners by adding {@code
 * last-login-timestamp}.
 *
 * <p>Configuration: - Provider ID: {@code last-login-timestamp} - Default user attribute: {@code
 * lastLoginTimestamp} - Override attribute name: {@code
 * --spi-events-listener--last-login-timestamp--attribute-name=...} The value must match {@code
 * ^[a-zA-Z][a-zA-Z0-9_]{0,63}$} and must not be a reserved user attribute ({@code id}, {@code
 * username}, {@code email}, {@code firstName}, {@code lastName}, {@code emailVerified}, {@code
 * enabled}, {@code locale}, {@code createdTimestamp}, {@code disabledReason}, {@code did}, {@code
 * is_temporary_admin}). Invalid values are rejected with a WARN and the default {@code
 * lastLoginTimestamp} is used instead.
 *
 * <p>After a successful login commit, attribute updates are scheduled on a small background thread
 * pool so the login HTTP response is not delayed by the best-effort write.
 *
 * <p>Limitations: - Attribute updates are best-effort and monotonic per Keycloak node, not
 * cluster-wide. - Do not rely on this attribute alone for audit or compliance; use Keycloak event
 * logs or a dedicated audit store if canonical login history is required.
 *
 * @see LastLoginTimestampListener
 * @see org.keycloak.events.EventListenerProviderFactory
 * @author Dean Grant
 * @since 1.0.0
 */
public class LastLoginTimestampListenerFactory implements EventListenerProviderFactory {

  private static final Logger LOG = Logger.getLogger(LastLoginTimestampListenerFactory.class);

  /** Provider ID registered with Keycloak: {@code last-login-timestamp}. */
  public static final String PROVIDER_ID = "last-login-timestamp";

  /** Default user attribute name: {@code lastLoginTimestamp}. */
  private static final String DEFAULT_ATTRIBUTE_NAME = "lastLoginTimestamp";

  private static final int EXECUTOR_THREADS = 4;

  /**
   * Allowed attribute name format: starts with a letter, then letters, digits, or underscores, up
   * to 64 characters total.
   */
  private static final Pattern ATTRIBUTE_NAME_PATTERN =
      Pattern.compile("^[a-zA-Z][a-zA-Z0-9_]{0,63}$");

  /** Reserved user attribute names that must not be overwritten. */
  private static final Set<String> RESERVED_ATTRIBUTE_NAMES =
      Set.of(
          UserModel.ID,
          UserModel.USERNAME,
          UserModel.EMAIL,
          UserModel.FIRST_NAME,
          UserModel.LAST_NAME,
          UserModel.EMAIL_VERIFIED,
          UserModel.ENABLED,
          UserModel.LOCALE,
          UserModel.CREATED_TIMESTAMP,
          UserModel.DISABLED_REASON,
          UserModel.DID,
          UserModel.IS_TEMP_ADMIN_ATTR_NAME);

  /** User attribute name; set in {@link #init(Config.Scope)} and passed to each listener. */
  private String attributeName = DEFAULT_ATTRIBUTE_NAME;

  /** Background pool for after-commit attribute updates. */
  private ExecutorService executor;

  /**
   * Creates a new listener instance for the given session.
   *
   * @param session the Keycloak session bound to the current request
   * @return a new {@link LastLoginTimestampListener}
   */
  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new LastLoginTimestampListener(session, attributeName, executor);
  }

  /**
   * Reads SPI configuration, sets the user attribute name, and starts the background executor used
   * for after-commit updates.
   *
   * <p>Null or blank values fall back to {@code lastLoginTimestamp} silently. A non-blank value
   * that fails validation (see {@link #isValidAttributeName}) is rejected with a WARN and the
   * default is used, so a misconfiguration cannot overwrite reserved or unrelated user attributes.
   *
   * @param config SPI scope; reads {@code attribute-name}, defaulting to {@code
   *     lastLoginTimestamp}.
   */
  @Override
  public void init(Config.Scope config) {
    String configured = config.get("attribute-name");
    attributeName = resolveAttributeName(configured);
    if (configured != null
        && !configured.trim().isEmpty()
        && !attributeName.equals(configured.trim())) {
      LOG.warnf(
          "Invalid attribute-name \"%s\"; falling back to \"%s\"",
          configured.trim(), DEFAULT_ATTRIBUTE_NAME);
    }
    executor = Executors.newFixedThreadPool(EXECUTOR_THREADS, new DaemonThreadFactory());
  }

  /**
   * Resolves the effective attribute name from the configured value.
   *
   * @param configured the raw configured value, may be {@code null}
   * @return the trimmed value when valid, otherwise {@code lastLoginTimestamp}
   */
  private static String resolveAttributeName(String configured) {
    if (configured == null || configured.trim().isEmpty()) {
      return DEFAULT_ATTRIBUTE_NAME;
    }
    String trimmed = configured.trim();
    return isValidAttributeName(trimmed) ? trimmed : DEFAULT_ATTRIBUTE_NAME;
  }

  /**
   * Returns whether an attribute name is safe to write to.
   *
   * @param name the trimmed candidate name
   * @return {@code true} if it matches the allowed pattern and is not a reserved user attribute
   */
  static boolean isValidAttributeName(String name) {
    return ATTRIBUTE_NAME_PATTERN.matcher(name).matches()
        && !RESERVED_ATTRIBUTE_NAMES.contains(name);
  }

  /** No post-initialization required. */
  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  /** Shuts down the background executor. */
  @Override
  public void close() {
    if (executor != null) {
      executor.shutdown();
    }
  }

  /**
   * Returns the provider ID used to enable this listener on a realm.
   *
   * @return {@link #PROVIDER_ID}
   */
  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  /**
   * Returns the effective user attribute name after {@link #init(Config.Scope)}.
   *
   * @return the resolved attribute name (default or validated override)
   */
  String resolvedAttributeName() {
    return attributeName;
  }

  private static final class DaemonThreadFactory implements ThreadFactory {

    private final AtomicInteger sequence = new AtomicInteger();

    @Override
    public Thread newThread(Runnable runnable) {
      Thread thread = new Thread(runnable, "last-login-timestamp-" + sequence.incrementAndGet());
      thread.setDaemon(true);
      return thread;
    }
  }
}
