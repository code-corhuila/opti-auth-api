package co.edu.corhuila.opti.auth.application.usecase;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.application.port.out.Created;
import co.edu.corhuila.opti.auth.application.port.out.IdGenerator;
import co.edu.corhuila.opti.auth.application.port.out.IdempotencyStore;
import co.edu.corhuila.opti.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.opti.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.opti.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.opti.auth.application.port.out.UserRepository;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.IssuedToken;
import co.edu.corhuila.opti.auth.domain.model.PasswordPolicy;
import co.edu.corhuila.opti.auth.domain.model.User;
import co.edu.corhuila.opti.auth.domain.model.Validation;
import co.edu.corhuila.opti.auth.domain.model.Violations;

/**
 * Sign-in, people management and service credentials. A failed sign-in never says whether the
 * user exists, is inactive or is locked: every cause answers the same 401.
 */
public class AuthService implements AuthUseCases {

    private static final String APP_USER = "APP_USER";
    private static final String INVALID_CREDENTIALS = "invalid credentials";
    private static final int MAX_SERVICE_TOKEN_DAYS = 90;
    private static final Pattern SERVICE_NAME = Pattern.compile("^[a-z0-9._-]{3,40}$");

    private final UserRepository users;
    private final PasswordHasher hasher;
    private final TokenIssuer tokens;
    private final IdempotencyStore keys;
    private final IdGenerator ids;
    private final UnitOfWork unitOfWork;
    private final Clock clock;
    private final Duration tokenTimeToLive;
    /** Hash compared when the user does not exist, so an unknown user takes as long as a known one. */
    private final String decoyHash;

    public AuthService(UserRepository users, PasswordHasher hasher, TokenIssuer tokens, IdempotencyStore keys,
                       IdGenerator ids, UnitOfWork unitOfWork, Clock clock, Duration tokenTimeToLive) {
        this.users = users;
        this.hasher = hasher;
        this.tokens = tokens;
        this.keys = keys;
        this.ids = ids;
        this.unitOfWork = unitOfWork;
        this.clock = clock;
        this.tokenTimeToLive = tokenTimeToLive;
        this.decoyHash = hasher.hash("decoy-" + UUID.randomUUID());
    }

    @Override
    public LoginResult login(String username, String password) {
        Violations v = new Violations();
        String name = v.check(() -> Validation.text(username == null ? null : username.toLowerCase(), "username", 1, 40));
        v.check(() -> Validation.required(blankToNull(password), "password"));
        v.throwIfAny();
        // The outcome is returned, not thrown: throwing inside the unit of work would roll back the failure counter.
        Optional<User> signedIn = unitOfWork.run(() -> authenticate(name, password));
        User user = signedIn.orElseThrow(() -> DomainException.unauthenticated(INVALID_CREDENTIALS));
        IssuedToken token = tokens.issue(user.id().toString(), List.of(user.role().name()), user.username(),
                tokenTimeToLive);
        return new LoginResult(token, user);
    }

    /** Runs inside one unit of work: the failure counter is updated under a row lock. Empty means refused. */
    private Optional<User> authenticate(String username, String password) {
        Optional<User> found = users.findByUsernameForUpdate(username);
        var now = clock.instant();
        if (found.isEmpty() || !found.get().active() || found.get().isLocked(now)) {
            hasher.matches(password, decoyHash);
            return Optional.empty();
        }
        User user = found.get();
        if (!hasher.matches(password, user.passwordHash())) {
            users.update(user.failedSignIn(now));
            return Optional.empty();
        }
        if (!user.hasSignInHistory()) {
            return Optional.of(user);
        }
        User signedIn = user.signedIn(now);
        users.update(signedIn);
        return Optional.of(signedIn);
    }

    @Override
    public User me(UUID userId) {
        return get(userId);
    }

    @Override
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        Violations v = new Violations();
        v.check(() -> Validation.required(blankToNull(currentPassword), "currentPassword"));
        User user = users.findById(userId).orElseThrow(() -> DomainException.notFound("user not found"));
        v.check(() -> PasswordPolicy.validate(newPassword, user.username(), "newPassword"));
        v.throwIfAny();
        if (!hasher.matches(currentPassword, user.passwordHash())) {
            throw DomainException.validation("currentPassword", "is not correct");
        }
        if (currentPassword.equals(newPassword)) {
            throw DomainException.validation("newPassword", "must be different from the current password");
        }
        users.update(user.withPasswordHash(hasher.hash(newPassword), clock.instant()));
    }

    @Override
    public Created<User> register(User.RegisterData data, String idempotencyKey) {
        Violations v = new Violations();
        String key = v.check(() -> Validation.idempotencyKey(idempotencyKey));
        User.Checked input = v.check(() -> User.check(data));
        v.throwIfAny();
        UUID id = ids.next();
        return unitOfWork.run(() -> {
            if (!keys.claim(key, APP_USER, id)) {
                return new Created<>(get(keys.find(key, APP_USER).orElseThrow()), false);
            }
            User user = User.register(id, input, hasher.hash(input.password()), clock.instant());
            users.insert(user);
            return new Created<>(user, true);
        });
    }

    @Override
    public User get(UUID id) {
        return users.findById(id).orElseThrow(() -> DomainException.notFound("user not found"));
    }

    @Override
    public PageResult<User> search(UserFilter filter, PageQuery page) {
        return users.search(filter, page);
    }

    @Override
    public User setActive(UUID id, boolean active, UUID actorId) {
        if (!active && id.equals(actorId)) {
            throw DomainException.rule("you cannot deactivate your own user");
        }
        User user = get(id);
        User updated = active ? user.activate(clock.instant()) : user.deactivate(clock.instant());
        users.update(updated);
        return updated;
    }

    @Override
    public User setSalesGoal(UUID id, Long salesGoalCents) {
        User updated = get(id).withSalesGoal(salesGoalCents, clock.instant());
        users.update(updated);
        return updated;
    }

    @Override
    public IssuedToken issueServiceToken(String name, Integer ttlDays) {
        Violations v = new Violations();
        String subject = v.check(() -> Validation.matching(name, "name", SERVICE_NAME,
                "must have 3 to 40 lower case letters, digits, dots, dashes or underscores"));
        Integer days = v.check(() -> Validation.intBetween(Validation.required(ttlDays, "ttlDays"), "ttlDays", 1,
                MAX_SERVICE_TOKEN_DAYS));
        v.throwIfAny();
        return tokens.issue("service:" + subject, List.of("SERVICE"), subject, Duration.ofDays(days));
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
