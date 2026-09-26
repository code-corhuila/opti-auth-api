package co.edu.corhuila.opti.auth.application.port.out;

/** One-way password hashing. The clear password never leaves the use case. */
public interface PasswordHasher {

    String hash(String password);

    boolean matches(String password, String hash);
}
