package me.deangrant.keycloak.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.utils.StringUtil;

class LastLoginTimestampListenerTest {

    private static final long NOW = 1_700_000_000_000L;

    @Test
    void nullValueIsMissing() {
        assertTrue(LastLoginTimestampListener.isMissingOrOlder(null, NOW));
    }

    @Test
    void blankValueIsMissing() {
        assertTrue(LastLoginTimestampListener.isMissingOrOlder("   ", NOW));
    }

    @Test
    void nonNumericValueIsReplaced() {
        assertTrue(LastLoginTimestampListener.isMissingOrOlder("not-a-number", NOW));
    }

    @Test
    void olderValueIsReplaced() {
        assertTrue(LastLoginTimestampListener.isMissingOrOlder(Long.toString(NOW - 1), NOW));
    }

    @Test
    void equalValueIsKept() {
        assertFalse(LastLoginTimestampListener.isMissingOrOlder(Long.toString(NOW), NOW));
    }

    @Test
    void newerValueIsKept() {
        assertFalse(LastLoginTimestampListener.isMissingOrOlder(Long.toString(NOW + 1), NOW));
    }

    @Test
    void sameRealmUserReturnsSameLock() {
        Object first = LastLoginTimestampListener.userLock("realm-a", "user-1");
        Object second = LastLoginTimestampListener.userLock("realm-a", "user-1");
        assertSame(first, second);
    }

    @Test
    void lockStripesAreFixedAndNonNull() {
        assertEquals(256, LastLoginTimestampListener.lockStripeCount());
        assertNotNull(LastLoginTimestampListener.userLock("realm-a", "user-1"));
        assertNotNull(LastLoginTimestampListener.userLock("realm-b", "user-2"));
    }

    @Test
    void formatEventWithErrorToleratesNullEventFields() {
        Event event = new Event();
        String message = LastLoginTimestampListener.formatEventWithError(
                event, new RuntimeException("boom"), "lastLoginTimestamp");
        assertNotNull(message);
        assertFalse(message.isBlank());
        assertTrue(message.contains("error="));
        assertTrue(message.contains("RuntimeException"));
    }

    @Test
    void formatEventWithErrorIncludesOnlyAllowlistedDetails() {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        Map<String, String> details = new HashMap<>();
        details.put(Details.AUTH_METHOD, "openid-connect");
        details.put(Details.IDENTITY_PROVIDER, "google");
        details.put(Details.USERNAME, "should-not-appear");
        event.setDetails(details);

        String message = LastLoginTimestampListener.formatEventWithError(
                event, new RuntimeException("boom"), "lastLoginTimestamp");

        assertTrue(message.contains(Details.AUTH_METHOD + "="));
        assertTrue(message.contains("openid-connect"));
        assertTrue(message.contains(Details.IDENTITY_PROVIDER + "="));
        assertTrue(message.contains("google"));
        assertFalse(message.contains(Details.USERNAME + "="));
        assertFalse(message.contains("should-not-appear"));
    }

    @Test
    void formatEventWithErrorOmitsSessionIdAndIpAddress() {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setSessionId("session-secret");
        event.setIpAddress("203.0.113.9");

        String message = LastLoginTimestampListener.formatEventWithError(
                event, new RuntimeException("boom"), "lastLoginTimestamp");

        assertFalse(message.contains("sessionId="));
        assertFalse(message.contains("ipAddress="));
        assertFalse(message.contains("session-secret"));
        assertFalse(message.contains("203.0.113.9"));
    }

    @Test
    void formatEventWithErrorSanitizesQuotesInDetailValues() {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        Map<String, String> details = new HashMap<>();
        details.put(Details.AUTH_METHOD, "say \"hi\"");
        event.setDetails(details);

        String message = LastLoginTimestampListener.formatEventWithError(
                event, new RuntimeException("boom"), "lastLoginTimestamp");
        String sanitized = StringUtil.sanitizeSpacesAndQuotes("say \"hi\"", '"');

        assertTrue(message.contains(Details.AUTH_METHOD + "=\"" + sanitized + "\""));
        assertFalse(message.contains(Details.AUTH_METHOD + "=\"say \"hi\"\""));
    }
}
