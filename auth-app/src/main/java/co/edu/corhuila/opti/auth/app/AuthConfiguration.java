package co.edu.corhuila.opti.auth.app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.support.TransactionTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import co.edu.corhuila.opti.auth.adapter.in.http.PublicPaths;
import co.edu.corhuila.opti.auth.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.opti.auth.adapter.out.persistence.IdempotencyKeys;
import co.edu.corhuila.opti.auth.adapter.out.persistence.JdbcUnitOfWork;
import co.edu.corhuila.opti.auth.adapter.out.persistence.JdbcUserRepository;
import co.edu.corhuila.opti.auth.adapter.out.persistence.UuidGenerator;
import co.edu.corhuila.opti.auth.adapter.out.security.BcryptPasswordHasher;
import co.edu.corhuila.opti.auth.adapter.out.security.Rs256TokenIssuer;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.application.port.out.IdGenerator;
import co.edu.corhuila.opti.auth.application.port.out.IdempotencyStore;
import co.edu.corhuila.opti.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.opti.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.opti.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.opti.auth.application.port.out.UserRepository;
import co.edu.corhuila.opti.auth.application.usecase.AuthService;

/**
 * Composition root: the only place that knows every concrete type. The numeric limits (server
 * timeouts, pool size, statement timeout, graceful shutdown) are declared with their value in
 * {@code application.yml}, next to this class.
 */
@Configuration
class AuthConfiguration {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    Rs256Verifier tokenVerifier(ObjectMapper json, Clock clock,
                                @Value("${jwt.public-key:}") String publicKey,
                                @Value("${jwt.public-key-file:}") String publicKeyFile) throws IOException {
        String pem = publicKey.isBlank() && !publicKeyFile.isBlank()
                ? Files.readString(Path.of(publicKeyFile)) : publicKey;
        if (pem.isBlank()) {
            throw new IllegalStateException("Set JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_FILE (public key of this service)");
        }
        return new Rs256Verifier(pem, json, clock);
    }

    @Bean
    TokenIssuer tokenIssuer(ObjectMapper json, Clock clock,
                            @Value("${auth.jwt.private-key:}") String privateKey,
                            @Value("${auth.jwt.private-key-file:}") String privateKeyFile) throws IOException {
        String pem = privateKey.isBlank() && !privateKeyFile.isBlank()
                ? Files.readString(Path.of(privateKeyFile)) : privateKey;
        if (pem.isBlank()) {
            throw new IllegalStateException("Set JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_FILE (private key of the identity service)");
        }
        return new Rs256TokenIssuer(pem, json, clock);
    }

    /** Sign-in is the only endpoint served without a token. */
    @Bean
    PublicPaths publicPaths() {
        return PublicPaths.with("/api/v1/auth/login");
    }

    @Bean
    IdempotencyStore idempotencyStore(JdbcClient jdbc) {
        return new IdempotencyKeys(jdbc);
    }

    @Bean
    UnitOfWork unitOfWork(TransactionTemplate transaction) {
        return new JdbcUnitOfWork(transaction);
    }

    @Bean
    IdGenerator idGenerator() {
        return new UuidGenerator();
    }

    @Bean
    PasswordHasher passwordHasher() {
        return new BcryptPasswordHasher();
    }

    @Bean
    UserRepository userRepository(JdbcClient jdbc) {
        return new JdbcUserRepository(jdbc);
    }

    @Bean
    AuthUseCases authUseCases(UserRepository users, PasswordHasher hasher, TokenIssuer tokens, IdempotencyStore keys,
                              IdGenerator ids, UnitOfWork unitOfWork, Clock clock,
                              @Value("${auth.jwt.token-ttl-minutes:60}") long tokenTtlMinutes) {
        return new AuthService(users, hasher, tokens, keys, ids, unitOfWork, clock, Duration.ofMinutes(tokenTtlMinutes));
    }
}
