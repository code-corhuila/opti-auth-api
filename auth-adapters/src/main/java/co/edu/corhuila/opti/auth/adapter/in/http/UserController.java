package co.edu.corhuila.opti.auth.adapter.in.http;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.RegisterUserRequest;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.SalesGoalRequest;
import co.edu.corhuila.opti.auth.adapter.in.http.AuthDtos.UserResponse;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases;
import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases.UserFilter;
import co.edu.corhuila.opti.auth.domain.model.Role;

import jakarta.servlet.http.HttpServletRequest;

/** People management. Everything here is for administrators. */
@RestController
@RequestMapping("/api/v1/users")
class UserController {

    private static final String USERS = "/api/v1/users";

    private final AuthUseCases useCases;

    UserController(AuthUseCases useCases) {
        this.useCases = useCases;
    }

    @PostMapping
    ResponseEntity<Responses.CreatedBody> register(HttpServletRequest http,
            @RequestHeader(value = "Idempotency-Key", required = false) String key,
            @RequestBody RegisterUserRequest body) {
        RequestRules.requireRole(http, Roles.ADMIN);
        var result = useCases.register(body.toData(), key);
        return Responses.created(result, result.value().id(), USERS);
    }

    /** Also open to a SERVICE caller: the worker lists sellers (role=SELLER) to check their sales goal. */
    @GetMapping
    PageResponse<UserResponse> search(HttpServletRequest http, @RequestParam(required = false) String q,
            @RequestParam(required = false) String role, @RequestParam(required = false) String active,
            @RequestParam(required = false) String page, @RequestParam(required = false) String limit) {
        RequestRules.requireRole(http, Roles.ADMIN, Roles.SERVICE);
        RequestRules.onlyParams(http, "q", "role", "active", "page", "limit");
        var filter = new UserFilter(q, parseRole(role), parseBoolean(active));
        return PageResponse.of(useCases.search(filter, RequestRules.page(page, limit)).map(UserResponse::from));
    }

    @GetMapping("/{id}")
    UserResponse get(HttpServletRequest http, @PathVariable String id) {
        RequestRules.requireRole(http, Roles.ADMIN, Roles.SERVICE);
        return UserResponse.from(useCases.get(RequestRules.uuid(id, "id")));
    }

    @PutMapping("/{id}/sales-goal")
    UserResponse setSalesGoal(HttpServletRequest http, @PathVariable String id, @RequestBody SalesGoalRequest body) {
        RequestRules.requireRole(http, Roles.ADMIN);
        return UserResponse.from(useCases.setSalesGoal(RequestRules.uuid(id, "id"), body.salesGoalCents()));
    }

    @PostMapping("/{id}/deactivate")
    UserResponse deactivate(HttpServletRequest http, @PathVariable String id) {
        RequestRules.requireRole(http, Roles.ADMIN);
        return UserResponse.from(useCases.setActive(RequestRules.uuid(id, "id"), false, AuthController.callerId(http)));
    }

    @PostMapping("/{id}/activate")
    UserResponse activate(HttpServletRequest http, @PathVariable String id) {
        RequestRules.requireRole(http, Roles.ADMIN);
        return UserResponse.from(useCases.setActive(RequestRules.uuid(id, "id"), true, AuthController.callerId(http)));
    }

    private static Role parseRole(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Role.valueOf(value);
        } catch (IllegalArgumentException e) {
            throw ApiException.validation("role", "must be ADMIN, SELLER or OPTOMETRIST");
        }
    }

    private static Boolean parseBoolean(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        if (!"true".equals(value) && !"false".equals(value)) {
            throw ApiException.validation("active", "must be true or false");
        }
        return Boolean.valueOf(value);
    }
}
