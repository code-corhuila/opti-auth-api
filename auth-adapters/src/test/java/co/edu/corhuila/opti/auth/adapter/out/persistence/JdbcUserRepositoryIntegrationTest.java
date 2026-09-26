package co.edu.corhuila.opti.auth.adapter.out.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

import co.edu.corhuila.opti.auth.adapter.out.security.BcryptPasswordHasher;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases.UserFilter;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.usecase.AuthService;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.Role;
import co.edu.corhuila.opti.auth.domain.model.User;

/**
 * Runs the real use cases over a real PostgreSQL carrying the schema of opti-auth-db and real bcrypt.
 * {@code TEST_DATABASE_URL} example: {@code jdbc:postgresql://localhost:5432/auth?user=x&password=y}.
 * Without it the test is skipped, not failed.
 */
@EnabledIfEnvironmentVariable(named = "TEST_DATABASE_URL", matches = ".+")
class JdbcUserRepositoryIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-42";

    private static AuthUseCases auth;
    private static JdbcUserRepository users;

    @BeforeAll
    static void connect() {
        var dataSource = new DriverManagerDataSource(System.getenv("TEST_DATABASE_URL"));
        dataSource.setSchema("auth");
        var jdbc = JdbcClient.create(dataSource);
        var transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        users = new JdbcUserRepository(jdbc);
        auth = new AuthService(users, new BcryptPasswordHasher(),
                (subject, roles, name, ttl) -> new co.edu.corhuila.opti.auth.domain.model.IssuedToken("t-" + subject, ttl.toSeconds()),
                new IdempotencyKeys(jdbc), new UuidGenerator(), new JdbcUnitOfWork(transaction), Clock.systemUTC(),
                Duration.ofMinutes(60));
    }

    @Test
    void registersAUserAndKeepsOnlyABcryptHash() {
        String username = username();

        User created = auth.register(new User.RegisterData(username, "Laura Ortega", PASSWORD, Role.SELLER), key()).value();
        User read = users.findByUsername(username).orElseThrow();

        assertThat(read.id()).isEqualTo(created.id());
        assertThat(read.role()).isEqualTo(Role.SELLER);
        assertThat(read.active()).isTrue();
        assertThat(read.passwordHash()).startsWith("$2").doesNotContain(PASSWORD);
        assertThat(read.createdAt()).isCloseTo(Instant.now(), org.assertj.core.api.Assertions.within(1, java.time.temporal.ChronoUnit.MINUTES));
    }

    @Test
    void sameKeyCreatesOneUserAndADuplicateUsernameReleasesItsKey() {
        String username = username();
        String key = key();
        var first = auth.register(new User.RegisterData(username, "Laura Ortega", PASSWORD, Role.SELLER), key);
        var replay = auth.register(new User.RegisterData(username, "Laura Ortega", PASSWORD, Role.SELLER), key);
        assertThat(replay.created()).isFalse();
        assertThat(replay.value().id()).isEqualTo(first.value().id());

        String otherKey = key();
        assertThatThrownBy(() -> auth.register(new User.RegisterData(username, "Otra Persona", PASSWORD, Role.ADMIN), otherKey))
                .isInstanceOf(DomainException.class);
        assertThat(auth.register(new User.RegisterData(username(), "Otra Persona", PASSWORD, Role.ADMIN), otherKey).created())
                .as("the key of the failed attempt was rolled back").isTrue();
    }

    @Test
    void loginCountsFailuresLocksAndResets() {
        String username = username();
        auth.register(new User.RegisterData(username, "Laura Ortega", PASSWORD, Role.OPTOMETRIST), key());

        for (int i = 0; i < User.MAX_FAILED_ATTEMPTS; i++) {
            assertThatThrownBy(() -> auth.login(username, "Wrong-Password-1")).isInstanceOf(DomainException.class);
        }
        User locked = users.findByUsername(username).orElseThrow();
        assertThat(locked.lockedUntil()).isAfter(Instant.now());
        assertThatThrownBy(() -> auth.login(username, PASSWORD)).as("locked").isInstanceOf(DomainException.class);

        users.update(locked.signedIn(Instant.now()));
        assertThat(auth.login(username, PASSWORD).token().value()).startsWith("t-");
        assertThat(users.findByUsername(username).orElseThrow().failedAttempts()).isZero();
    }

    @Test
    void searchFiltersByRoleStateAndTextAndEscapesWildcards() {
        String tag = UUID.randomUUID().toString().substring(0, 8);
        auth.register(new User.RegisterData("adm." + tag, "Ana " + tag, PASSWORD, Role.ADMIN), key());
        User seller = auth.register(new User.RegisterData("sel." + tag, "Sara " + tag, PASSWORD, Role.SELLER), key()).value();
        auth.setActive(seller.id(), false, UUID.randomUUID());

        assertThat(auth.search(new UserFilter(tag, Role.ADMIN, null), PageQuery.first(10)).total()).isEqualTo(1);
        assertThat(auth.search(new UserFilter(tag, null, false), PageQuery.first(10)).data())
                .extracting(User::username).containsExactly("sel." + tag);
        assertThat(auth.search(new UserFilter(tag, null, null), PageQuery.first(10)).total()).isEqualTo(2);
        assertThat(auth.search(new UserFilter("%" + tag, null, null), PageQuery.first(10)).total()).isZero();
    }

    @Test
    void passwordChangeIsPersisted() {
        String username = username();
        User user = auth.register(new User.RegisterData(username, "Laura Ortega", PASSWORD, Role.SELLER), key()).value();

        auth.changePassword(user.id(), PASSWORD, "Another-Pass-77");

        assertThat(auth.login(username, "Another-Pass-77")).isNotNull();
        assertThatThrownBy(() -> auth.login(username, PASSWORD)).isInstanceOf(DomainException.class);
    }

    private static String username() {
        return "it." + UUID.randomUUID().toString().substring(0, 12);
    }

    private static String key() {
        return "it-" + UUID.randomUUID();
    }
}
