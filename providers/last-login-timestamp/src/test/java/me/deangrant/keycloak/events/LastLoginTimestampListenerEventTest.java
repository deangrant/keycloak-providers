package me.deangrant.keycloak.events;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransaction;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class LastLoginTimestampListenerEventTest {

    private static final String REALM_ID = "realm-1";
    private static final String USER_ID = "user-1";
    private static final String ATTRIBUTE = "lastLoginTimestamp";
    private static final long BASE_TIME = 1_700_000_000_000L;

    private ExecutorService concurrencyPool;

    @AfterEach
    void tearDown() {
        if (concurrencyPool != null) {
            concurrencyPool.shutdownNow();
        }
    }

    @Test
    void loginEventWritesAttributeAfterCommit() {
        Fixture fixture = Fixture.create(Runnable::run);
        Event event = loginEvent(BASE_TIME);

        fixture.listener.onEvent(event);
        fixture.commitDeferred();

        assertEquals(Long.toString(BASE_TIME), fixture.attribute.get());
        verify(fixture.sessionFactory, atLeastOnce()).create();
    }

    @Test
    void loginWithoutUserIdIsIgnored() {
        Fixture fixture = Fixture.create(Runnable::run);
        Event event = loginEvent(BASE_TIME);
        event.setUserId(null);

        fixture.listener.onEvent(event);
        fixture.commitDeferred();

        verify(fixture.sessionFactory, never()).create();
        assertNull(fixture.attribute.get());
    }

    @Test
    void loginWithoutRealmIdIsIgnored() {
        Fixture fixture = Fixture.create(Runnable::run);
        Event event = loginEvent(BASE_TIME);
        event.setRealmId(null);

        fixture.listener.onEvent(event);
        fixture.commitDeferred();

        verify(fixture.sessionFactory, never()).create();
        assertNull(fixture.attribute.get());
    }

    @Test
    void loginErrorIsIgnored() {
        assertNonLoginIgnored(EventType.LOGIN_ERROR);
    }

    @Test
    void logoutIsIgnored() {
        assertNonLoginIgnored(EventType.LOGOUT);
    }

    @Test
    void impersonateIsIgnored() {
        assertNonLoginIgnored(EventType.IMPERSONATE);
    }

    @Test
    void writesWhenAttributeMissingOlderOrInvalid() {
        Fixture fixture = Fixture.create(Runnable::run);

        fixture.listener.onEvent(loginEvent(BASE_TIME));
        fixture.commitDeferred();
        assertEquals(Long.toString(BASE_TIME), fixture.attribute.get());

        fixture = Fixture.create(Runnable::run);
        fixture.attribute.set(Long.toString(BASE_TIME - 10));
        fixture.listener.onEvent(loginEvent(BASE_TIME));
        fixture.commitDeferred();
        assertEquals(Long.toString(BASE_TIME), fixture.attribute.get());

        fixture = Fixture.create(Runnable::run);
        fixture.attribute.set("not-a-number");
        fixture.listener.onEvent(loginEvent(BASE_TIME));
        fixture.commitDeferred();
        assertEquals(Long.toString(BASE_TIME), fixture.attribute.get());
    }

    @Test
    void skipsWhenAttributeEqualOrNewer() {
        Fixture fixture = Fixture.create(Runnable::run);
        fixture.attribute.set(Long.toString(BASE_TIME));
        fixture.listener.onEvent(loginEvent(BASE_TIME));
        fixture.commitDeferred();
        verify(fixture.user, never()).setSingleAttribute(eq(ATTRIBUTE), anyString());
        assertEquals(Long.toString(BASE_TIME), fixture.attribute.get());

        fixture = Fixture.create(Runnable::run);
        fixture.attribute.set(Long.toString(BASE_TIME + 50));
        fixture.listener.onEvent(loginEvent(BASE_TIME));
        fixture.commitDeferred();
        verify(fixture.user, never()).setSingleAttribute(eq(ATTRIBUTE), anyString());
        assertEquals(Long.toString(BASE_TIME + 50), fixture.attribute.get());
    }

    @Test
    void updateExceptionIsLoggedAndNotRethrown() {
        Fixture fixture = Fixture.create(Runnable::run);
        when(fixture.user.getFirstAttribute(ATTRIBUTE)).thenThrow(new RuntimeException("storage down"));

        fixture.listener.onEvent(loginEvent(BASE_TIME));
        assertDoesNotThrow(fixture::commitDeferred);
        verify(fixture.user, never()).setSingleAttribute(eq(ATTRIBUTE), anyString());
    }

    @Test
    void concurrentLoginsLeaveMaxTimestamp() throws Exception {
        concurrencyPool = Executors.newFixedThreadPool(8);
        List<Long> timestamps = List.of(
                BASE_TIME + 1,
                BASE_TIME + 40,
                BASE_TIME + 7,
                BASE_TIME + 25,
                BASE_TIME + 3,
                BASE_TIME + 18,
                BASE_TIME + 33,
                BASE_TIME + 12);

        AtomicReference<String> sharedAttribute = new AtomicReference<>();
        KeycloakSessionFactory sharedFactory = mock(KeycloakSessionFactory.class);
        stubSharedFactory(sharedFactory, sharedAttribute);

        CountDownLatch ready = new CountDownLatch(timestamps.size());
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(timestamps.size());
        List<Thread> threads = new ArrayList<>();

        for (Long timestamp : timestamps) {
            Thread thread = new Thread(() -> {
                try {
                    Fixture fixture = Fixture.createWithoutFactoryStub(
                            concurrencyPool, sharedFactory, sharedAttribute);
                    fixture.listener.onEvent(loginEvent(timestamp));
                    ready.countDown();
                    start.await(5, TimeUnit.SECONDS);
                    fixture.commitDeferred();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                } finally {
                    done.countDown();
                }
            });
            threads.add(thread);
            thread.start();
        }

        assertTrue(ready.await(5, TimeUnit.SECONDS));
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        // commitDeferred only schedules work on the pool; wait for updates to finish.
        concurrencyPool.shutdown();
        assertTrue(concurrencyPool.awaitTermination(10, TimeUnit.SECONDS));

        long expectedMax = timestamps.stream().mapToLong(Long::longValue).max().orElseThrow();
        assertEquals(Long.toString(expectedMax), sharedAttribute.get());

        for (Thread thread : threads) {
            thread.join(1_000);
        }
    }

    private void assertNonLoginIgnored(EventType type) {
        Fixture fixture = Fixture.create(Runnable::run);
        Event event = loginEvent(BASE_TIME);
        event.setType(type);

        fixture.listener.onEvent(event);
        fixture.commitDeferred();

        verify(fixture.sessionFactory, never()).create();
        assertNull(fixture.attribute.get());
    }

    private static Event loginEvent(long time) {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setRealmId(REALM_ID);
        event.setUserId(USER_ID);
        event.setTime(time);
        return event;
    }

    private static void stubSharedFactory(KeycloakSessionFactory sessionFactory,
            AtomicReference<String> attribute) {
        when(sessionFactory.create()).thenAnswer(invocation -> {
            KeycloakSession workSession = mock(KeycloakSession.class);
            KeycloakTransactionManager workTx = mock(KeycloakTransactionManager.class);
            RealmProvider realms = mock(RealmProvider.class);
            UserProvider users = mock(UserProvider.class);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);

            when(workSession.getTransactionManager()).thenReturn(workTx);
            when(workSession.realms()).thenReturn(realms);
            when(workSession.users()).thenReturn(users);
            when(realms.getRealm(REALM_ID)).thenReturn(realm);
            when(users.getUserById(realm, USER_ID)).thenReturn(user);
            when(user.getFirstAttribute(ATTRIBUTE)).thenAnswer(i -> attribute.get());
            doAnswer(i -> {
                attribute.set(i.getArgument(1));
                return null;
            }).when(user).setSingleAttribute(eq(ATTRIBUTE), anyString());
            return workSession;
        });
    }

    private static final class Fixture {
        final KeycloakSessionFactory sessionFactory;
        final UserModel user;
        final AtomicReference<String> attribute;
        final LastLoginTimestampListener listener;
        final AbstractKeycloakTransaction deferredTx;

        private Fixture(KeycloakSessionFactory sessionFactory, UserModel user,
                AtomicReference<String> attribute, LastLoginTimestampListener listener,
                AbstractKeycloakTransaction deferredTx) {
            this.sessionFactory = sessionFactory;
            this.user = user;
            this.attribute = attribute;
            this.listener = listener;
            this.deferredTx = deferredTx;
        }

        static Fixture create(Executor executor) {
            AtomicReference<String> attribute = new AtomicReference<>();
            KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
            KeycloakSession workSession = mock(KeycloakSession.class);
            UserModel user = stubWorkSession(sessionFactory, workSession, attribute);
            return createListener(executor, sessionFactory, workSession, user, attribute);
        }

        static Fixture createWithoutFactoryStub(Executor executor,
                KeycloakSessionFactory sessionFactory, AtomicReference<String> attribute) {
            return createListener(executor, sessionFactory, null, null, attribute);
        }

        private static Fixture createListener(Executor executor,
                KeycloakSessionFactory sessionFactory, KeycloakSession workSession,
                UserModel user, AtomicReference<String> attribute) {
            KeycloakSession requestSession = mock(KeycloakSession.class);
            KeycloakTransactionManager requestTx = mock(KeycloakTransactionManager.class);
            when(requestSession.getKeycloakSessionFactory()).thenReturn(sessionFactory);
            when(requestSession.getTransactionManager()).thenReturn(requestTx);

            ArgumentCaptor<KeycloakTransaction> enlisted =
                    ArgumentCaptor.forClass(KeycloakTransaction.class);
            doAnswer(invocation -> null).when(requestTx).enlistAfterCompletion(enlisted.capture());

            LastLoginTimestampListener listener =
                    new LastLoginTimestampListener(requestSession, ATTRIBUTE, executor);
            AbstractKeycloakTransaction deferredTx =
                    (AbstractKeycloakTransaction) enlisted.getValue();
            return new Fixture(sessionFactory, user, attribute, listener, deferredTx);
        }

        private static UserModel stubWorkSession(KeycloakSessionFactory sessionFactory,
                KeycloakSession workSession, AtomicReference<String> attribute) {
            KeycloakTransactionManager workTx = mock(KeycloakTransactionManager.class);
            RealmProvider realms = mock(RealmProvider.class);
            UserProvider users = mock(UserProvider.class);
            RealmModel realm = mock(RealmModel.class);
            UserModel user = mock(UserModel.class);

            when(sessionFactory.create()).thenReturn(workSession);
            when(workSession.getTransactionManager()).thenReturn(workTx);
            when(workSession.realms()).thenReturn(realms);
            when(workSession.users()).thenReturn(users);
            when(realms.getRealm(REALM_ID)).thenReturn(realm);
            when(users.getUserById(realm, USER_ID)).thenReturn(user);
            when(user.getFirstAttribute(ATTRIBUTE)).thenAnswer(i -> attribute.get());
            doAnswer(i -> {
                attribute.set(i.getArgument(1));
                return null;
            }).when(user).setSingleAttribute(eq(ATTRIBUTE), anyString());
            return user;
        }

        void commitDeferred() {
            deferredTx.begin();
            deferredTx.commit();
        }
    }
}
