package co.edu.corhuila.opti.auth.app;

import java.time.Duration;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceTransactionManagerAutoConfiguration;
import org.springframework.context.annotation.Bean;

import com.fasterxml.jackson.databind.ObjectMapper;

import co.edu.corhuila.opti.auth.adapter.in.http.PublicPaths;
import co.edu.corhuila.opti.auth.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.opti.auth.adapter.out.persistence.UuidGenerator;
import co.edu.corhuila.opti.auth.adapter.out.security.BcryptPasswordHasher;
import co.edu.corhuila.opti.auth.adapter.out.security.Rs256TokenIssuer;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.application.port.in.NotificationUseCases;
import co.edu.corhuila.opti.auth.application.usecase.AuthService;
import co.edu.corhuila.opti.auth.application.usecase.NotificationService;
import co.edu.corhuila.opti.auth.testsupport.DirectUnitOfWork;
import co.edu.corhuila.opti.auth.testsupport.Fixtures;
import co.edu.corhuila.opti.auth.testsupport.InMemoryAuth;
import co.edu.corhuila.opti.auth.testsupport.InMemoryIdempotencyStore;
import co.edu.corhuila.opti.auth.testsupport.InMemoryNotifications;
import co.edu.corhuila.opti.auth.testsupport.TestClock;

/**
 * Boots only the HTTP adapter over in-memory storage, with the real bcrypt hasher and the real
 * RS256 signer: what login returns is a token the same service then accepts.
 */
@SpringBootApplication(scanBasePackages = "co.edu.corhuila.opti.auth.adapter.in.http",
        exclude = {DataSourceAutoConfiguration.class, DataSourceTransactionManagerAutoConfiguration.class})
class HttpTestApplication {

    @Bean
    TestClock clock() {
        return TestClock.at(Fixtures.START);
    }

    @Bean
    Rs256Verifier verifier(ObjectMapper json, TestClock clock) {
        return new Rs256Verifier(TestTokens.publicKeyPem(), json, clock);
    }

    @Bean
    PublicPaths publicPaths() {
        return PublicPaths.with("/api/v1/auth/login");
    }

    @Bean
    AuthUseCases authUseCases(ObjectMapper json, TestClock clock) {
        var keys = new InMemoryIdempotencyStore();
        return new AuthService(new InMemoryAuth.Users(), new BcryptPasswordHasher(),
                new Rs256TokenIssuer(TestTokens.privateKeyPem(), json, clock), keys, new UuidGenerator(),
                new DirectUnitOfWork(keys), clock, Duration.ofMinutes(60));
    }

    @Bean
    NotificationUseCases notificationUseCases(TestClock clock) {
        var keys = new InMemoryIdempotencyStore();
        return new NotificationService(new InMemoryNotifications(), keys, new UuidGenerator(),
                new DirectUnitOfWork(keys), clock);
    }
}
