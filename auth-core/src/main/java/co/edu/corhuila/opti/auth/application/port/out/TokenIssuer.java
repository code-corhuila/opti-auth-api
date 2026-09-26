package co.edu.corhuila.opti.auth.application.port.out;

import java.time.Duration;
import java.util.List;

import co.edu.corhuila.opti.auth.domain.model.IssuedToken;

/** Signs access tokens. Only the identity service owns the private key. */
public interface TokenIssuer {

    IssuedToken issue(String subject, List<String> roles, String displayName, Duration timeToLive);
}
