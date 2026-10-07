package co.edu.corhuila.opti.auth.adapter.in.http;

import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.ChangePasswordRequest;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.LoginRequest;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.LoginResponse;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.ServiceTokenRequest;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.TokenResponse;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.UserResponse;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.domain.model.DomainException;

import jakarta.servlet.http.HttpServletRequest;

/** Sign-in, current user, password change and service credentials. Only login is public. */
@RestController
@RequestMapping("/api/v1/auth")
class AuthController {

    private final AuthUseCases useCases;

    AuthController(AuthUseCases useCases) {
        this.useCases = useCases;
    }

    @PostMapping("/login")
    LoginResponse login(@RequestBody LoginRequest body) {
        var result = useCases.login(body.username(), body.password());
        return LoginResponse.from(result.token(), result.user());
    }

    @GetMapping("/me")
    UserResponse me(HttpServletRequest http) {
        return UserResponse.from(useCases.me(callerId(http)));
    }

    @PostMapping("/change-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void changePassword(HttpServletRequest http, @RequestBody ChangePasswordRequest body) {
        useCases.changePassword(callerId(http), body.currentPassword(), body.newPassword());
    }

    /** Issues the credential of a service (worker, workflow). The token is shown once and never stored. */
    @PostMapping("/service-tokens")
    TokenResponse serviceToken(HttpServletRequest http, @RequestBody ServiceTokenRequest body) {
        RequestRules.requireRole(http, Roles.ADMIN);
        return TokenResponse.from(useCases.issueServiceToken(body.name(), body.ttlDays()));
    }

    /** The user of the token; a service token has no user row, so it has no "me". */
    static UUID callerId(HttpServletRequest http) {
        String subject = RequestRules.caller(http).subject();
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw DomainException.notFound("the token does not belong to a user");
        }
    }
}
