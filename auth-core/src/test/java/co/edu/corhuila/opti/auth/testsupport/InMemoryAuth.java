package co.edu.corhuila.opti.auth.testsupport;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases.UserFilter;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.opti.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.opti.auth.application.port.out.UserRepository;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.IssuedToken;
import co.edu.corhuila.opti.auth.domain.model.User;

/** In-memory fakes of the identity ports, used to test the core without a database or real hashing. */
public final class InMemoryAuth {

    private InMemoryAuth() {
    }

    /** Users keyed by id; the username is unique like the table's constraint. */
    public static class Users implements UserRepository {

        private final Map<UUID, User> byId = new HashMap<>();

        @Override
        public void insert(User user) {
            if (findByUsername(user.username()).isPresent()) {
                throw DomainException.rule("the username is already taken");
            }
            byId.put(user.id(), user);
        }

        @Override
        public Optional<User> findById(UUID id) {
            return Optional.ofNullable(byId.get(id));
        }

        @Override
        public Optional<User> findByUsername(String username) {
            return byId.values().stream().filter(u -> u.username().equals(username)).findFirst();
        }

        @Override
        public Optional<User> findByUsernameForUpdate(String username) {
            return findByUsername(username);
        }

        @Override
        public PageResult<User> search(UserFilter filter, PageQuery page) {
            List<User> matches = byId.values().stream()
                    .filter(u -> filter.role() == null || u.role() == filter.role())
                    .filter(u -> filter.active() == null || u.active() == filter.active())
                    .filter(u -> filter.query() == null || filter.query().isBlank()
                            || (u.username() + " " + u.fullName().toLowerCase()).contains(filter.query().toLowerCase()))
                    .sorted(Comparator.comparing(User::createdAt).reversed().thenComparing(User::id))
                    .toList();
            int from = Math.min(page.offset(), matches.size());
            int to = Math.min(from + page.limit(), matches.size());
            return new PageResult<>(matches.subList(from, to), page.page(), page.limit(), matches.size());
        }

        @Override
        public void update(User user) {
            byId.put(user.id(), user);
        }
    }

    /** Reversible fake: fast, and lets a test see what was hashed. Real bcrypt has its own adapter test. */
    public static class Hasher implements PasswordHasher {

        @Override
        public String hash(String password) {
            return "hashed:" + password;
        }

        @Override
        public boolean matches(String password, String hash) {
            return hash.equals("hashed:" + password);
        }
    }

    /** Issues readable fake tokens and remembers the last claims for assertions. */
    public static class Tokens implements TokenIssuer {

        public String lastSubject;
        public List<String> lastRoles;
        public Duration lastTimeToLive;

        @Override
        public IssuedToken issue(String subject, List<String> roles, String displayName, Duration timeToLive) {
            lastSubject = subject;
            lastRoles = roles;
            lastTimeToLive = timeToLive;
            return new IssuedToken("token-for-" + subject, timeToLive.toSeconds());
        }
    }

    /** Convenience: a user stored with a known password, created at a given instant. */
    public static User existing(UUID id, String username, String password, co.edu.corhuila.opti.auth.domain.model.Role role,
                                Instant now) {
        return User.rehydrate(id, username, "Demo " + username, null, "hashed:" + password, role, true, 0, null,
                null, now, now);
    }
}
