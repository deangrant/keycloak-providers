package me.deangrant.keycloak.events;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

class LastLoginTimestampListenerFactoryTest {

    @Test
    void defaultAttributeNameIsValid() {
        assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("lastLoginTimestamp"));
    }

    @Test
    void customAttributeNameIsValid() {
        assertTrue(LastLoginTimestampListenerFactory.isValidAttributeName("myCustomAttribute"));
    }

    @Test
    void existingReservedNamesAreRejected() {
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.USERNAME));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.EMAIL));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.FIRST_NAME));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.LAST_NAME));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.LOCALE));
    }

    @Test
    void coreFieldNamesAreRejected() {
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.EMAIL_VERIFIED));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.ENABLED));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.CREATED_TIMESTAMP));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.DISABLED_REASON));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.DID));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.IS_TEMP_ADMIN_ATTR_NAME));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName(UserModel.ID));
    }

    @Test
    void patternInvalidNameIsRejected() {
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("1startsWithDigit"));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("has-dash"));
        assertFalse(LastLoginTimestampListenerFactory.isValidAttributeName("kc.email.pending"));
    }
}
