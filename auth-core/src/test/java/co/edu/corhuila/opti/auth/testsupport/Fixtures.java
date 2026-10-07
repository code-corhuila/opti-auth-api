package co.edu.corhuila.opti.auth.testsupport;

import java.time.Duration;

import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.application.usecase.AuthService;
import co.edu.corhuila.opti.auth.domain.model.Role;
import co.edu.corhuila.opti.auth.domain.model.User;

/** Ready-made valid inputs and a wired service over the fakes. */
public final class Fixtures {

    public static final String START = "2026-09-29T15:00:00Z";
    public static final String PASSWORD = "Correct-Horse-42";

    private Fixtures() {
    }

    /** The service and the fakes behind it, so a test can look inside. */
    public record Wired(AuthUseCases service, InMemoryAuth.Users users, InMemoryAuth.Tokens tokens) {
    }

    public static Wired wired(TestClock clock) {
        var users = new InMemoryAuth.Users();
        var tokens = new InMemoryAuth.Tokens();
        var keys = new InMemoryIdempotencyStore();
        var service = new AuthService(users, new InMemoryAuth.Hasher(), tokens, keys, new SequentialIds(),
                new DirectUnitOfWork(keys), clock, Duration.ofMinutes(60));
        return new Wired(service, users, tokens);
    }

    public static User.RegisterData user(String username) {
        return new User.RegisterData(username, "Laura Ortega", PASSWORD, Role.SELLER);
    }
}
