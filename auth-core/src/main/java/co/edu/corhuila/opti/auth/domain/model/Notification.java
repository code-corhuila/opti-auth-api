package co.edu.corhuila.opti.auth.domain.model;

import java.time.Instant;
import java.util.UUID;

/** A notification for one user. Never modified except to mark it read. */
public final class Notification {

    private final UUID id;
    private final UUID userId;
    private final NotificationType type;
    private final String message;
    private final Instant readAt;
    private final Instant createdAt;

    private Notification(UUID id, UUID userId, NotificationType type, String message, Instant readAt,
                         Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.type = type;
        this.message = message;
        this.readAt = readAt;
        this.createdAt = createdAt;
    }

    /** Raw input, before validation. */
    public record Data(UUID userId, NotificationType type, String message) {
    }

    public static Notification create(UUID id, Data data, Instant now) {
        Violations v = new Violations();
        UUID userId = v.check(() -> Validation.required(data.userId(), "userId"));
        NotificationType type = v.check(() -> Validation.required(data.type(), "type"));
        String message = v.check(() -> Validation.text(data.message(), "message", 1, 300));
        v.throwIfAny();
        return new Notification(id, userId, type, message, null, now);
    }

    public static Notification rehydrate(UUID id, UUID userId, NotificationType type, String message,
                                         Instant readAt, Instant createdAt) {
        return new Notification(id, userId, type, message, readAt, createdAt);
    }

    public boolean isRead() {
        return readAt != null;
    }

    /** Marking an already-read notification read again changes nothing. */
    public Notification markRead(Instant now) {
        return isRead() ? this : new Notification(id, userId, type, message, now, createdAt);
    }

    public UUID id() {
        return id;
    }

    public UUID userId() {
        return userId;
    }

    public NotificationType type() {
        return type;
    }

    public String message() {
        return message;
    }

    public Instant readAt() {
        return readAt;
    }

    public Instant createdAt() {
        return createdAt;
    }
}
