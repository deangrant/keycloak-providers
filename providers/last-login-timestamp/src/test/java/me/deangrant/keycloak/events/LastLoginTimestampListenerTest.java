package me.deangrant.keycloak.events;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

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
}
