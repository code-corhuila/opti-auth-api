package co.edu.corhuila.opti.auth.application.usecase;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases.UserFilter;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.ErrorKind;
import co.edu.corhuila.opti.auth.domain.model.FieldError;
import co.edu.corhuila.opti.auth.domain.model.Role;
import co.edu.corhuila.opti.auth.domain.model.User;
import co.edu.corhuila.opti.auth.testsupport.Fixtures;
import co.edu.corhuila.opti.auth.testsupport.TestClock;

class AuthServiceTest {

    private static final String KEY = "register-0001";

    private TestClock clock;
    private Fixtures.Wired auth;

    @BeforeEach
    void setUp() {
        clock = TestClock.at(Fixtures.START);
        auth = Fixtures.wired(clock);
    }

    // ---- registering users ----------------------------------------------------------------

    @Test
    void registersAnActiveUserStoringOnlyTheHash() {
        var created = auth.service().register(Fixtures.user("laura.ortega"), KEY);

        User user = created.value();
        assertThat(created.created()).isTrue();
        assertThat(user.active()).isTrue();
        assertThat(user.username()).isEqualTo("laura.ortega");
        assertThat(user.passwordHash()).isEqualTo("hashed:" + Fixtures.PASSWORD).doesNotContain("Correct-Horse-42x");
    }

    @Test
    void usernamesAreLowerCasedAndUnique() {
        auth.service().register(Fixtures.user("Laura.Ortega"), KEY);

        assertThat(auth.users().findByUsername("laura.ortega")).isPresent();
        assertThatThrownBy(() -> auth.service().register(Fixtures.user("LAURA.ortega"), "register-0002"))
                .isInstanceOfSatisfying(DomainException.class,
                        e -> assertThat(e.kind()).isEqualTo(ErrorKind.BUSINESS_RULE_VIOLATION));
    }

    @Test
    void repeatingTheKeyReturnsTheSameUser() {
        var first = auth.service().register(Fixtures.user("laura.ortega"), KEY);
        var replay = auth.service().register(Fixtures.user("laura.ortega"), KEY);

        assertThat(replay.created()).isFalse();
        assertThat(replay.value().id()).isEqualTo(first.value().id());
    }

    @Test
    void reportsEveryInvalidFieldAtOnce() {
        var invalid = new User.RegisterData("A!", " ", "short", null);

        assertThatThrownBy(() -> auth.service().register(invalid, "x"))
                .isInstanceOfSatisfying(DomainException.class, e ->
                        assertThat(e.fields()).extracting(FieldError::field).containsExactlyInAnyOrder(
                                "Idempotency-Key", "username", "fullName", "password", "role"));
    }

    @Test
    void passwordPolicyRequiresLengthMixAndNotTheUsername() {
        for (String weak : List.of("short1A", "alllowercase123", "ALLUPPERCASE123", "NoDigitsHereAtAll")) {
            assertThatThrownBy(() -> auth.service().register(
                    new User.RegisterData("laura.ortega", "Laura Ortega", weak, Role.SELLER), "register-" + weak))
                    .as(weak).isInstanceOf(DomainException.class);
        }
        assertThatThrownBy(() -> auth.service().register(
                new User.RegisterData("Laura12345A", "Laura Ortega", "laura12345a", Role.SELLER), "register-0009"))
                .isInstanceOf(DomainException.class);
        assertThatThrownBy(() -> auth.service().register(
                new User.RegisterData("laura.ortega", "Laura Ortega", "Aa1" + "x".repeat(80), Role.SELLER), "register-0010"))
                .isInstanceOf(DomainException.class);
    }

    // ---- login ----------------------------------------------------------------------------

    @Test
    void loginIssuesATokenWithTheRoleAndTheConfiguredLifetime() {
        User user = auth.service().register(Fixtures.user("laura.ortega"), KEY).value();

        var result = auth.service().login("Laura.Ortega", Fixtures.PASSWORD);

        assertThat(result.user().id()).isEqualTo(user.id());
        assertThat(result.token().value()).isEqualTo("token-for-" + user.id());
        assertThat(result.token().expiresInSeconds()).isEqualTo(3600);
        assertThat(auth.tokens().lastRoles).containsExactly("SELLER");
        assertThat(auth.tokens().lastTimeToLive).isEqualTo(Duration.ofMinutes(60));
    }

    @Test
    void everyKindOfFailureAnswersTheSameUnauthenticatedError() {
        auth.service().register(Fixtures.user("laura.ortega"), KEY);
        User inactive = auth.service().register(Fixtures.user("pedro.perez"), "register-0002").value();
        auth.service().setActive(inactive.id(), false, UUID.randomUUID());

        for (String[] attempt : new String[][] {
                {"laura.ortega", "Wrong-Password-1"}, {"nobody", Fixtures.PASSWORD}, {"pedro.perez", Fixtures.PASSWORD}}) {
            assertThatThrownBy(() -> auth.service().login(attempt[0], attempt[1]))
                    .isInstanceOfSatisfying(DomainException.class, e -> {
                        assertThat(e.kind()).isEqualTo(ErrorKind.UNAUTHENTICATED);
                        assertThat(e.getMessage()).isEqualTo("invalid credentials");
                    });
        }
    }

    @Test
    void loginRequiresBothFields() {
        assertThatThrownBy(() -> auth.service().login(" ", null))
                .isInstanceOfSatisfying(DomainException.class, e -> {
                    assertThat(e.kind()).isEqualTo(ErrorKind.VALIDATION);
                    assertThat(e.fields()).extracting(FieldError::field).containsExactlyInAnyOrder("username", "password");
                });
    }

    @Test
    void fiveFailuresLockTheUserEvenForTheRightPasswordUntilTheLockExpires() {
        auth.service().register(Fixtures.user("laura.ortega"), KEY);
        for (int i = 0; i < User.MAX_FAILED_ATTEMPTS; i++) {
            assertThatThrownBy(() -> auth.service().login("laura.ortega", "Wrong-Password-1")).isInstanceOf(DomainException.class);
        }

        assertThatThrownBy(() -> auth.service().login("laura.ortega", Fixtures.PASSWORD))
                .as("locked: the right password is refused too").isInstanceOf(DomainException.class);

        clock.advance(User.LOCK_TIME.plusSeconds(1));
        assertThat(auth.service().login("laura.ortega", Fixtures.PASSWORD).user().username()).isEqualTo("laura.ortega");
        assertThat(auth.users().findByUsername("laura.ortega").orElseThrow().failedAttempts()).isZero();
    }

    @Test
    void aSuccessfulLoginResetsTheFailureCounter() {
        auth.service().register(Fixtures.user("laura.ortega"), KEY);
        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> auth.service().login("laura.ortega", "Wrong-Password-1")).isInstanceOf(DomainException.class);
        }
        auth.service().login("laura.ortega", Fixtures.PASSWORD);

        for (int i = 0; i < 4; i++) {
            assertThatThrownBy(() -> auth.service().login("laura.ortega", "Wrong-Password-1")).isInstanceOf(DomainException.class);
        }
        assertThat(auth.service().login("laura.ortega", Fixtures.PASSWORD)).isNotNull();
    }

    // ---- password change ------------------------------------------------------------------

    @Test
    void changePasswordChecksTheCurrentOneAndThePolicy() {
        User user = auth.service().register(Fixtures.user("laura.ortega"), KEY).value();

        assertThatThrownBy(() -> auth.service().changePassword(user.id(), "Wrong-Password-1", "Another-Pass-77"))
                .isInstanceOfSatisfying(DomainException.class,
                        e -> assertThat(e.fields()).extracting(FieldError::field).containsExactly("currentPassword"));
        assertThatThrownBy(() -> auth.service().changePassword(user.id(), Fixtures.PASSWORD, "weak"))
                .isInstanceOfSatisfying(DomainException.class,
                        e -> assertThat(e.fields()).extracting(FieldError::field).containsExactly("newPassword"));
        assertThatThrownBy(() -> auth.service().changePassword(user.id(), Fixtures.PASSWORD, Fixtures.PASSWORD))
                .isInstanceOf(DomainException.class);

        auth.service().changePassword(user.id(), Fixtures.PASSWORD, "Another-Pass-77");

        assertThat(auth.service().login("laura.ortega", "Another-Pass-77")).isNotNull();
        assertThatThrownBy(() -> auth.service().login("laura.ortega", Fixtures.PASSWORD)).isInstanceOf(DomainException.class);
    }

    // ---- management -----------------------------------------------------------------------

    @Test
    void deactivatingBlocksLoginActivatingRestoresItAndYouCannotDeactivateYourself() {
        User user = auth.service().register(Fixtures.user("laura.ortega"), KEY).value();

        assertThatThrownBy(() -> auth.service().setActive(user.id(), false, user.id()))
                .isInstanceOfSatisfying(DomainException.class,
                        e -> assertThat(e.kind()).isEqualTo(ErrorKind.BUSINESS_RULE_VIOLATION));
        auth.service().setActive(user.id(), false, UUID.randomUUID());
        assertThatThrownBy(() -> auth.service().login("laura.ortega", Fixtures.PASSWORD)).isInstanceOf(DomainException.class);
        auth.service().setActive(user.id(), true, UUID.randomUUID());
        assertThat(auth.service().login("laura.ortega", Fixtures.PASSWORD)).isNotNull();
    }

    @Test
    void listsNewestFirstWithFilters() {
        auth.service().register(Fixtures.user("first.user"), "register-0001");
        clock.advance(Duration.ofMinutes(1));
        auth.service().register(new User.RegisterData("second.admin", "Second Admin", Fixtures.PASSWORD, Role.ADMIN), "register-0002");

        var all = auth.service().search(new UserFilter(null, null, null), PageQuery.first(20));
        var admins = auth.service().search(new UserFilter(null, Role.ADMIN, null), PageQuery.first(20));
        var byName = auth.service().search(new UserFilter("first", null, true), PageQuery.first(20));

        assertThat(all.data()).extracting(User::username).containsExactly("second.admin", "first.user");
        assertThat(admins.total()).isEqualTo(1);
        assertThat(byName.data()).extracting(User::username).containsExactly("first.user");
    }

    @Test
    void unknownUserIsNotFound() {
        assertThatThrownBy(() -> auth.service().get(UUID.randomUUID())).isInstanceOfSatisfying(DomainException.class,
                e -> assertThat(e.kind()).isEqualTo(ErrorKind.NOT_FOUND));
        assertThatThrownBy(() -> auth.service().me(UUID.randomUUID())).isInstanceOf(DomainException.class);
    }

    // ---- sales goal -------------------------------------------------------------------------

    @Test
    void settingTheSalesGoalPersistsItAndClearingItSetsItBackToNull() {
        User seller = auth.service().register(Fixtures.user("sofia.mora"), KEY).value();

        User withGoal = auth.service().setSalesGoal(seller.id(), 500_000_00L);
        assertThat(withGoal.salesGoalCents()).isEqualTo(500_000_00L);
        assertThat(auth.service().get(seller.id()).salesGoalCents()).isEqualTo(500_000_00L);

        User cleared = auth.service().setSalesGoal(seller.id(), null);
        assertThat(cleared.salesGoalCents()).isNull();
    }

    @Test
    void aNegativeSalesGoalIsRejected() {
        User seller = auth.service().register(Fixtures.user("sofia.mora"), KEY).value();

        assertThatThrownBy(() -> auth.service().setSalesGoal(seller.id(), -1L))
                .isInstanceOfSatisfying(DomainException.class, e ->
                        assertThat(e.fields()).extracting(FieldError::field).containsExactly("salesGoalCents"));
    }

    // ---- service tokens -------------------------------------------------------------------

    @Test
    void serviceTokenHasTheServiceRoleAndABoundedLifetime() {
        var token = auth.service().issueServiceToken("opti-worker", 30);

        assertThat(auth.tokens().lastSubject).isEqualTo("service:opti-worker");
        assertThat(auth.tokens().lastRoles).containsExactly("SERVICE");
        assertThat(token.expiresInSeconds()).isEqualTo(Duration.ofDays(30).toSeconds());
        assertThatThrownBy(() -> auth.service().issueServiceToken("Bad Name!", 91))
                .isInstanceOfSatisfying(DomainException.class, e ->
                        assertThat(e.fields()).extracting(FieldError::field).containsExactlyInAnyOrder("name", "ttlDays"));
    }
}
