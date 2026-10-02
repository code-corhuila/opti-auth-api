package co.edu.corhuila.opti.auth.adapter.out.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import co.edu.corhuila.opti.auth.adapter.in.http.Rs256Verifier;
import co.edu.corhuila.opti.auth.domain.model.IssuedToken;

/** The signer and the verifier are written apart (auth signs, every service verifies): they must agree. */
class TokenAndHashTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Clock NOW = Clock.fixed(Instant.parse("2026-09-29T15:00:00Z"), ZoneOffset.UTC);

    @Test
    void aTokenSignedByTheIssuerIsAcceptedByTheVerifierWithItsClaims() throws Exception {
        KeyPair keys = newKeys();
        var issuer = new Rs256TokenIssuer(pem("PRIVATE KEY", keys.getPrivate().getEncoded()), JSON, NOW);
        var verifier = new Rs256Verifier(pem("PUBLIC KEY", keys.getPublic().getEncoded()), JSON, NOW);

        IssuedToken token = issuer.issue("user-42", List.of("ADMIN"), "laura", Duration.ofMinutes(60));
        var user = verifier.verify(token.value());

        assertThat(token.expiresInSeconds()).isEqualTo(3600);
        assertThat(user.subject()).isEqualTo("user-42");
        assertThat(user.roles()).containsExactly("ADMIN");
        String header = new String(Base64.getUrlDecoder().decode(token.value().split("\\.")[0]));
        assertThat(JSON.readTree(header).path("alg").asText()).isEqualTo("RS256");
    }

    @Test
    void theVerifierRejectsATokenSignedByAnotherKeyAndAnExpiredOne() throws Exception {
        KeyPair mine = newKeys();
        KeyPair stranger = newKeys();
        var verifier = new Rs256Verifier(pem("PUBLIC KEY", mine.getPublic().getEncoded()), JSON, NOW);
        var forged = new Rs256TokenIssuer(pem("PRIVATE KEY", stranger.getPrivate().getEncoded()), JSON, NOW)
                .issue("user-42", List.of("ADMIN"), "x", Duration.ofMinutes(5));
        var expired = new Rs256TokenIssuer(pem("PRIVATE KEY", mine.getPrivate().getEncoded()), JSON,
                Clock.fixed(NOW.instant().minus(Duration.ofHours(3)), ZoneOffset.UTC))
                .issue("user-42", List.of("ADMIN"), "x", Duration.ofMinutes(5));

        assertThatThrownBy(() -> verifier.verify(forged.value())).isInstanceOf(Rs256Verifier.InvalidTokenException.class);
        assertThatThrownBy(() -> verifier.verify(expired.value())).isInstanceOf(Rs256Verifier.InvalidTokenException.class);
    }

    @Test
    void theIssuerRefusesAKeyThatIsNotAPrivateKey() {
        assertThatThrownBy(() -> new Rs256TokenIssuer("not a key", JSON, NOW)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void bcryptHashesAreSaltedAndVerifiable() {
        var hasher = new BcryptPasswordHasher();

        String first = hasher.hash("Correct-Horse-42");
        String second = hasher.hash("Correct-Horse-42");

        assertThat(first).startsWith("$2").isNotEqualTo(second);
        assertThat(hasher.matches("Correct-Horse-42", first)).isTrue();
        assertThat(hasher.matches("correct-horse-42", first)).isFalse();
    }

    private static KeyPair newKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----";
    }
}
