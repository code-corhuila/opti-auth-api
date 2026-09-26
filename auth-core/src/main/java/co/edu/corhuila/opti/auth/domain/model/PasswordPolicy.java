package co.edu.corhuila.opti.auth.domain.model;

import java.nio.charset.StandardCharsets;

/**
 * Rules for a new password: long enough, mixed characters, within the 72 bytes bcrypt reads, and
 * never the username. The clear text is validated here and then only its hash is kept.
 */
public final class PasswordPolicy {

    static final int MIN_LENGTH = 10;
    static final int MAX_BYTES = 72;

    private PasswordPolicy() {
    }

    /** Returns the password when it is acceptable, otherwise a validation error on {@code field}. */
    public static String validate(String password, String username, String field) {
        if (password == null || password.length() < MIN_LENGTH) {
            throw DomainException.validation(field, "must have at least " + MIN_LENGTH + " characters");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
            throw DomainException.validation(field, "must have at most " + MAX_BYTES + " bytes");
        }
        boolean upper = password.chars().anyMatch(Character::isUpperCase);
        boolean lower = password.chars().anyMatch(Character::isLowerCase);
        boolean digit = password.chars().anyMatch(Character::isDigit);
        if (!(upper && lower && digit)) {
            throw DomainException.validation(field, "must mix upper case, lower case and digits");
        }
        if (username != null && password.equalsIgnoreCase(username)) {
            throw DomainException.validation(field, "must not be the username");
        }
        return password;
    }
}
