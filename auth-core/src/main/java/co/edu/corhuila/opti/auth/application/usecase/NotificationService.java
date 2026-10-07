package co.edu.corhuila.opti.auth.application.usecase;

import java.time.Clock;
import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.in.NotificationUseCases;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.application.port.out.Created;
import co.edu.corhuila.opti.auth.application.port.out.IdGenerator;
import co.edu.corhuila.opti.auth.application.port.out.IdempotencyStore;
import co.edu.corhuila.opti.auth.application.port.out.NotificationRepository;
import co.edu.corhuila.opti.auth.application.port.out.UnitOfWork;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.Notification;
import co.edu.corhuila.opti.auth.domain.model.Validation;
import co.edu.corhuila.opti.auth.domain.model.Violations;

/**
 * Notifications. Creation claims its idempotency key first, so a worker that calls this once per
 * check (for example "sales-goal:{sellerId}:2026-10") never creates the same notification twice.
 */
public class NotificationService implements NotificationUseCases {

    private static final String NOTIFICATION = "NOTIFICATION";

    private final NotificationRepository notifications;
    private final IdempotencyStore keys;
    private final IdGenerator ids;
    private final UnitOfWork unitOfWork;
    private final Clock clock;

    public NotificationService(NotificationRepository notifications, IdempotencyStore keys, IdGenerator ids,
                               UnitOfWork unitOfWork, Clock clock) {
        this.notifications = notifications;
        this.keys = keys;
        this.ids = ids;
        this.unitOfWork = unitOfWork;
        this.clock = clock;
    }

    @Override
    public Created<Notification> create(Notification.Data data, String idempotencyKey) {
        Violations v = new Violations();
        String key = v.check(() -> Validation.idempotencyKey(idempotencyKey));
        Notification notification = v.check(() -> Notification.create(ids.next(), data, clock.instant()));
        v.throwIfAny();
        return unitOfWork.run(() -> {
            if (!keys.claim(key, NOTIFICATION, notification.id())) {
                UUID existing = keys.find(key, NOTIFICATION).orElseThrow();
                return new Created<>(notifications.findById(existing).orElseThrow(), false);
            }
            notifications.insert(notification);
            return new Created<>(notification, true);
        });
    }

    @Override
    public PageResult<Notification> mine(UUID userId, PageQuery page) {
        return notifications.listFor(userId, page);
    }

    @Override
    public Notification markRead(UUID id, UUID userId) {
        Notification notification = notifications.findById(id)
                .orElseThrow(() -> DomainException.notFound("notification not found"));
        if (!notification.userId().equals(userId)) {
            throw DomainException.notFound("notification not found");
        }
        Notification read = notification.markRead(clock.instant());
        notifications.update(read);
        return read;
    }
}
