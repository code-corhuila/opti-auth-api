package co.edu.corhuila.opti.auth.adapter.out.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import co.edu.corhuila.opti.auth.application.port.out.PasswordHasher;

/** bcrypt with a work factor of 12: about a quarter of a second per check, slow enough to make guessing costly. */
public class BcryptPasswordHasher implements PasswordHasher {

    private static final int STRENGTH = 12;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(STRENGTH);

    @Override
    public String hash(String password) {
        return encoder.encode(password);
    }

    @Override
    public boolean matches(String password, String hash) {
        return encoder.matches(password, hash);
    }
}
