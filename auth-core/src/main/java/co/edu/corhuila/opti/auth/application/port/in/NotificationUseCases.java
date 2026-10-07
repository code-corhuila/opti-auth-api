package co.edu.corhuila.opti.auth.application.port.in;

import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.out.Created;
import co.edu.corhuila.opti.auth.domain.model.Notification;

/** What the identity service offers about notifications: every person reads only their own. */
public interface NotificationUseCases {

    /** Created by a SERVICE caller (the worker). The idempotency key keeps one notification per event. */
    Created<Notification> create(Notification.Data data, String idempotencyKey);

    PageResult<Notification> mine(UUID userId, PageQuery page);

    /** Marking someone else's notification read is refused. */
    Notification markRead(UUID id, UUID userId);
}
