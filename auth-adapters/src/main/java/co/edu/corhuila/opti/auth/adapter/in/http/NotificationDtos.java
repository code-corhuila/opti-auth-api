package co.edu.corhuila.opti.auth.adapter.in.http;

import java.time.Instant;
import java.util.UUID;

import co.edu.corhuila.opti.auth.domain.model.Notification;
import co.edu.corhuila.opti.auth.domain.model.NotificationType;

/**
 * Request and response objects of the public contract. The domain entity is never serialized
 * directly, so renaming an internal field cannot break a client.
 */
final class NotificationDtos {

    private NotificationDtos() {
    }

    record CreateNotificationRequest(UUID userId, NotificationType type, String message) {

        Notification.Data toData() {
            return new Notification.Data(userId, type, message);
        }
    }

    record NotificationResponse(UUID id, NotificationType type, String message, boolean read, Instant readAt,
                                Instant createdAt) {

        static NotificationResponse from(Notification n) {
            return new NotificationResponse(n.id(), n.type(), n.message(), n.isRead(), n.readAt(), n.createdAt());
        }
    }
}
