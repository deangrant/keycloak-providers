package me.deangrant.keycloak.events;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import org.jboss.logging.Logger;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

/**
 * Event listener that records each user's most recent login as a Unix epoch
 * timestamp.
 *
 * On {@link EventType#LOGIN}, queues the event and writes the event time
 * (milliseconds since epoch) to the user attribute configured by
 * {@link LastLoginTimestampListenerFactory} after the login transaction
 * commits, in a separate transaction. A per-user lock serializes the
 * read-compare-write on that node so only missing, invalid, or strictly older
 * stored values are replaced for concurrent logins of the same user on that
 * server.
 *
 * This is a best-effort side effect. In a multi-node deployment, concurrent
 * logins routed to different nodes may still race at the database layer.
 * Failures are caught and logged at WARN; they never abort the login flow or
 * roll back authentication.
 *
 * Failure logs are written to the {@code org.keycloak.events} logger using
 * Keycloak's native {@code key="value"} format. Only allowlisted non-sensitive
 * event detail keys are included; {@code sessionId} and {@code ipAddress} are
 * omitted from failure logs.
 *
 * @see LastLoginTimestampListenerFactory
 * @see org.keycloak.events.EventListenerProvider
 * @author Dean Grant
 * @since 1.0.0
 */
public class LastLoginTimestampListener implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger("org.keycloak.events");
    private static final char QUOTE = '"';
    private static final List<String> ALLOWED_FAILURE_LOG_DETAIL_KEYS = List.of(
            Details.AUTH_METHOD,
            Details.IDENTITY_PROVIDER
    );
    private static final Map<String, Object> USER_LOCKS = new ConcurrentHashMap<>();

    private final KeycloakSession session;
    private final String attributeName;
    private final DeferredLoginTransaction tx = new DeferredLoginTransaction();

    /**
     * @param session        Keycloak session used for user lookup and attribute writes
     * @param attributeName  user attribute to store the last-login timestamp
     */
    public LastLoginTimestampListener(KeycloakSession session, String attributeName) {
        this.session = session;
        this.attributeName = attributeName;
        session.getTransactionManager().enlistAfterCompletion(tx);
    }

    /**
     * Handles user events. Only {@link EventType#LOGIN} is processed.
     *
     * Queues the event for deferred attribute update after login commits.
     *
     * @param event the Keycloak user event
     */
    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.LOGIN
                && event.getUserId() != null
                && event.getRealmId() != null) {
            tx.addEvent(event);
        }
    }

    /**
     * Persists the last-login timestamp after the login transaction commits.
     *
     * Acquires a per-user lock and performs read-compare-write in a single fresh
     * transaction so unrelated users never contend, same-user writes stay
     * serialized on this node, and write failures cannot roll back
     * authentication. The stored value is replaced only when it is missing,
     * invalid, or strictly older than the event time. Cross-node monotonicity
     * is not guaranteed; concurrent logins on different Keycloak nodes may
     * still commit out of order at the database.
     *
     * @param event the queued login event
     */
    private void updateLastLoginTimestamp(Event event) {
        String realmId = event.getRealmId();
        String userId = event.getUserId();
        long newTimestamp = event.getTime();

        try {
            synchronized (userLock(realmId, userId)) {
                runInTransaction(session.getKeycloakSessionFactory(), s -> {
                    RealmModel realm = s.realms().getRealm(realmId);
                    if (realm == null) {
                        return;
                    }
                    UserModel user = s.users().getUserById(realm, userId);
                    if (user != null) {
                        String currentTimestamp = user.getFirstAttribute(attributeName);
                        if (isMissingOrOlder(currentTimestamp, newTimestamp)) {
                            user.setSingleAttribute(attributeName, Long.toString(newTimestamp));
                        }
                    }
                });
            }
        } catch (Exception e) {
            LOG.warn(formatEventWithError(event, e), e);
        }
    }

    /**
     * Runs {@code task} in a fresh Keycloak session/transaction using public
     * session APIs only (no private model utilities).
     *
     * @param factory the session factory
     * @param task    work to run inside the new transaction
     */
    private static void runInTransaction(KeycloakSessionFactory factory, Consumer<KeycloakSession> task) {
        try (KeycloakSession s = factory.create()) {
            s.getTransactionManager().begin();
            try {
                task.accept(s);
            } catch (RuntimeException e) {
                s.getTransactionManager().setRollbackOnly();
                throw e;
            }
        }
    }

    /**
     * Returns the per-user lock for a realm/user pair.
     *
     * @param realmId the realm identifier
     * @param userId  the user identifier
     * @return a dedicated lock object serializing updates for that user
     */
    private static Object userLock(String realmId, String userId) {
        return USER_LOCKS.computeIfAbsent(realmId + ':' + userId, k -> new Object());
    }

    /**
     * Returns whether the stored timestamp should be replaced by a newer value.
     *
     * @param currentTimestamp the existing attribute value, if any
     * @param newTimestamp     the login event time in milliseconds since epoch
     * @return {@code true} if the attribute is missing, blank, invalid, or
     *         strictly older than {@code newTimestamp}
     */
    static boolean isMissingOrOlder(String currentTimestamp, long newTimestamp) {
        if (currentTimestamp == null || currentTimestamp.isBlank()) {
            return true;
        }
        try {
            return Long.parseLong(currentTimestamp) < newTimestamp;
        } catch (NumberFormatException e) {
            return true;
        }
    }

    /**
     * Admin events are not handled.
     *
     * @param event                  the admin event (ignored)
     * @param includeRepresentation  whether to include representation (ignored)
     */
    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
    }

    /** No resources to release. */
    @Override
    public void close() {
    }

    /**
     * Builds a Keycloak-style event log line with an {@code error} field
     * appended.
     *
     * Includes standard event fields and allowlisted non-sensitive details only.
     * Does not include {@code sessionId} or {@code ipAddress}.
     *
     * @param event the original login event
     * @param e     the exception that caused the attribute update to fail
     * @return a comma-separated {@code key="value"} log message
     */
    private String formatEventWithError(Event event, Exception e) {
        StringBuilder sb = new StringBuilder();
        appendField(sb, "type", event.getType().toString());
        appendField(sb, "realmId", event.getRealmId());
        appendField(sb, "realmName", event.getRealmName());
        appendField(sb, "clientId", event.getClientId());
        appendField(sb, "userId", event.getUserId());
        if (event.getDetails() != null) {
            for (String key : ALLOWED_FAILURE_LOG_DETAIL_KEYS) {
                String value = event.getDetails().get(key);
                if (value != null) {
                    appendField(sb, key, value);
                }
            }
        }
        appendField(sb, "error",
                "failed to update " + attributeName
                        + " attribute (" + e.getClass().getSimpleName() + ")");
        return sb.toString();
    }

    /**
     * Appends a single quoted {@code key="value"} field to the log message
     * buffer.
     *
     * @param sb    the message buffer
     * @param key   the field name
     * @param value the field value (may be {@code null})
     */
    private void appendField(StringBuilder sb, String key, String value) {
        if (sb.length() > 0) {
            sb.append(", ");
        }
        sb.append(StringUtil.sanitizeSpacesAndQuotes(key, null));
        sb.append('=');
        sb.append(QUOTE);
        if (value != null) {
            sb.append(StringUtil.sanitizeSpacesAndQuotes(value, QUOTE));
        }
        sb.append(QUOTE);
    }

    /**
     * Queues login events and processes them after the enclosing Keycloak
     * transaction commits successfully.
     */
    private final class DeferredLoginTransaction extends AbstractKeycloakTransaction {

        private final List<Event> events = new ArrayList<>();

        void addEvent(Event event) {
            events.add(event);
        }

        @Override
        protected void commitImpl() {
            for (Event event : events) {
                updateLastLoginTimestamp(event);
            }
        }

        @Override
        protected void rollbackImpl() {
            events.clear();
        }
    }
}
