package co.edu.corhuila.opti.auth.domain.model;

/** A signed access token and how long it lives, in seconds. */
public record IssuedToken(String value, long expiresInSeconds) {
}
