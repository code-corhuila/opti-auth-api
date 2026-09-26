package co.edu.corhuila.opti.auth.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * A person who can sign in. Pure domain object. It keeps the count of consecutive failed sign-ins
 * and locks itself for a while after too many, so guessing a password is slow.
 */
public final class User {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final Duration LOCK_TIME = Duration.ofMinutes(15);

    private static final Pattern USERNAME = Pattern.compile("^[a-z0-9._-]{3,40}$");

    private final UUID id;
    private final String username;
    private final String fullName;
    private final String passwordHash;
    private final Role role;
    private final boolean active;
    private final int failedAttempts;
    private final Instant lockedUntil;
    private final Instant createdAt;
    private final Instant updatedAt;

    private User(UUID id, String username, String fullName, String passwordHash, Role role, boolean active,
                 int failedAttempts, Instant lockedUntil, Instant createdAt, Instant updatedAt) {
        this.id = id;
        this.username = username;
        this.fullName = fullName;
        this.passwordHash = passwordHash;
        this.role = role;
        this.active = active;
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    /** Raw input to register a user, before validation. {@code password} is clear text and is never stored. */
    public record RegisterData(String username, String fullName, String password, Role role) {
    }

    /** What passed validation: the password is checked, not kept. */
    public record Checked(String username, String fullName, String password, Role role) {
    }

    /** Validates every field at once so the client gets all the problems, not one per attempt. */
    public static Checked check(RegisterData data) {
        Violations v = new Violations();
        String username = v.check(() -> normalizedUsername(data.username()));
        String fullName = v.check(() -> Validation.text(data.fullName(), "fullName", 2, 120));
        String password = v.check(() -> PasswordPolicy.validate(data.password(), username, "password"));
        Role role = v.check(() -> Validation.required(data.role(), "role"));
        v.throwIfAny();
        return new Checked(username, fullName, password, role);
    }

    public static User register(UUID id, Checked input, String passwordHash, Instant now) {
        return new User(id, input.username(), input.fullName(), passwordHash, input.role(), true, 0, null, now, now);
    }

    public static User rehydrate(UUID id, String username, String fullName, String passwordHash, Role role,
                                 boolean active, int failedAttempts, Instant lockedUntil, Instant createdAt,
                                 Instant updatedAt) {
        return new User(id, username, fullName, passwordHash, role, active, failedAttempts, lockedUntil, createdAt,
                updatedAt);
    }

    /** The username as it is stored and compared: trimmed and lower case. */
    public static String normalizedUsername(String raw) {
        return Validation.matching(raw == null ? null : raw.toLowerCase(), "username", USERNAME,
                "must have 3 to 40 letters, digits, dots, dashes or underscores");
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** One more failed sign-in; the fifth in a row locks the user for {@link #LOCK_TIME}. */
    public User failedSignIn(Instant now) {
        int attempts = failedAttempts + 1;
        Instant lock = attempts >= MAX_FAILED_ATTEMPTS ? now.plus(LOCK_TIME) : lockedUntil;
        int stored = attempts >= MAX_FAILED_ATTEMPTS ? 0 : attempts;
        return new User(id, username, fullName, passwordHash, role, active, stored, lock, createdAt, now);
    }

    public boolean hasSignInHistory() {
        return failedAttempts > 0 || lockedUntil != null;
    }

    /** A good sign-in clears the failures and any lock that already expired. */
    public User signedIn(Instant now) {
        return new User(id, username, fullName, passwordHash, role, active, 0, null, createdAt, now);
    }

    public User withPasswordHash(String newHash, Instant now) {
        return new User(id, username, fullName, newHash, role, active, 0, null, createdAt, now);
    }

    public User deactivate(Instant now) {
        return new User(id, username, fullName, passwordHash, role, false, failedAttempts, lockedUntil, createdAt, now);
    }

    public User activate(Instant now) {
        return new User(id, username, fullName, passwordHash, role, true, 0, null, createdAt, now);
    }

    public UUID id() {
        return id;
    }

    public String username() {
        return username;
    }

    public String fullName() {
        return fullName;
    }

    public String passwordHash() {
        return passwordHash;
    }

    public Role role() {
        return role;
    }

    public boolean active() {
        return active;
    }

    public int failedAttempts() {
        return failedAttempts;
    }

    public Instant lockedUntil() {
        return lockedUntil;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant updatedAt() {
        return updatedAt;
    }
}
