package co.edu.corhuila.opti.auth.adapter.in.http;

import java.time.Instant;
import java.util.UUID;

import co.edu.corhuila.opti.auth.domain.model.IssuedToken;
import co.edu.corhuila.opti.auth.domain.model.Role;
import co.edu.corhuila.opti.auth.domain.model.User;

/**
 * Request and response objects of the public contract. The domain entities are never serialized
 * directly: the password hash and the lock state can never leak by renaming or adding a field.
 */
final class AuthDtos {

    private static final String BEARER = "Bearer";

    private AuthDtos() {
    }

    record LoginRequest(String username, String password) {
    }

    record ChangePasswordRequest(String currentPassword, String newPassword) {
    }

    record RegisterUserRequest(String username, String fullName, String password, Role role) {

        User.RegisterData toData() {
            return new User.RegisterData(username, fullName, password, role);
        }
    }

    record ServiceTokenRequest(String name, Integer ttlDays) {
    }

    record UserResponse(UUID id, String username, String fullName, Role role, boolean active, Instant createdAt,
                        Instant updatedAt) {

        static UserResponse from(User u) {
            return new UserResponse(u.id(), u.username(), u.fullName(), u.role(), u.active(), u.createdAt(),
                    u.updatedAt());
        }
    }

    record TokenResponse(String accessToken, String tokenType, long expiresIn) {

        static TokenResponse from(IssuedToken token) {
            return new TokenResponse(token.value(), BEARER, token.expiresInSeconds());
        }
    }

    record LoginResponse(String accessToken, String tokenType, long expiresIn, UserResponse user) {

        static LoginResponse from(IssuedToken token, User user) {
            return new LoginResponse(token.value(), BEARER, token.expiresInSeconds(), UserResponse.from(user));
        }
    }
}
