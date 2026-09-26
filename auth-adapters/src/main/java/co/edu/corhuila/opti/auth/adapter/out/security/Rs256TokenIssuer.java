package co.edu.corhuila.opti.auth.adapter.out.security;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import co.edu.corhuila.opti.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.opti.auth.domain.model.IssuedToken;

/**
 * Signs JWTs with RS256 using the private key of the identity service. The header is fixed, so a
 * token can never claim another algorithm; every other service verifies with the public key only.
 */
public class Rs256TokenIssuer implements TokenIssuer {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final String ISSUER = "opti-auth";

    private final PrivateKey privateKey;
    private final ObjectMapper json;
    private final Clock clock;

    public Rs256TokenIssuer(String privateKeyPem, ObjectMapper json, Clock clock) {
        this.privateKey = parse(privateKeyPem);
        this.json = json;
        this.clock = clock;
    }

    @Override
    public IssuedToken issue(String subject, List<String> roles, String displayName, Duration timeToLive) {
        Instant now = clock.instant();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", ISSUER);
        claims.put("sub", subject);
        claims.put("roles", roles);
        claims.put("name", displayName);
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plus(timeToLive).getEpochSecond());
        try {
            String header = B64.encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String payload = B64.encodeToString(json.writeValueAsBytes(claims));
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            String token = header + "." + payload + "." + B64.encodeToString(signature.sign());
            return new IssuedToken(token, timeToLive.toSeconds());
        } catch (GeneralSecurityException | JsonProcessingException e) {
            throw new IllegalStateException("could not sign the token", e);
        }
    }

    private static PrivateKey parse(String pem) {
        try {
            String body = pem.replace("\\n", "\n")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("JWT private key is not a valid PKCS#8 RSA key (PEM)", e);
        }
    }
}
