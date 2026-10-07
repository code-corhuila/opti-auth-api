package co.edu.corhuila.opti.auth.adapter.in.http;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import co.edu.corhuila.opti.auth.adapter.in.http.NotificationDtos.CreateNotificationRequest;
import co.edu.corhuila.opti.auth.adapter.in.http.NotificationDtos.NotificationResponse;
import co.edu.corhuila.opti.auth.application.port.in.NotificationUseCases;

import jakarta.servlet.http.HttpServletRequest;

/** HTTP adapter of the notification use cases. Shape and role checks here; business rules in the core. */
@RestController
@RequestMapping("/api/v1/notifications")
class NotificationController {

    private static final String NOTIFICATIONS = "/api/v1/notifications";

    private final NotificationUseCases useCases;

    NotificationController(NotificationUseCases useCases) {
        this.useCases = useCases;
    }

    /** Only a SERVICE caller creates notifications (the worker, once it detects the event). */
    @PostMapping
    ResponseEntity<Responses.CreatedBody> create(HttpServletRequest http,
            @RequestHeader(value = "Idempotency-Key", required = false) String key,
            @RequestBody CreateNotificationRequest body) {
        RequestRules.requireRole(http, Roles.SERVICE);
        var result = useCases.create(body.toData(), key);
        return Responses.created(result, result.value().id(), NOTIFICATIONS);
    }

    /** Always the caller's own notifications; there is no sellerId or userId query parameter to abuse. */
    @GetMapping
    PageResponse<NotificationResponse> mine(HttpServletRequest http, @RequestParam(required = false) String page,
            @RequestParam(required = false) String limit) {
        RequestRules.requireRole(http, Roles.ADMIN, Roles.SELLER, Roles.OPTOMETRIST);
        RequestRules.onlyParams(http, "page", "limit");
        var userId = AuthController.callerId(http);
        return PageResponse.of(useCases.mine(userId, RequestRules.page(page, limit)).map(NotificationResponse::from));
    }

    @PostMapping("/{id}/read")
    NotificationResponse markRead(HttpServletRequest http, @PathVariable String id) {
        RequestRules.requireRole(http, Roles.ADMIN, Roles.SELLER, Roles.OPTOMETRIST);
        var userId = AuthController.callerId(http);
        return NotificationResponse.from(useCases.markRead(RequestRules.uuid(id, "id"), userId));
    }
}
