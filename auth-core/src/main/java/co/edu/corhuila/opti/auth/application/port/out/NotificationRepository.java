package co.edu.corhuila.opti.auth.application.port.out;

import java.util.Optional;
import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.domain.model.Notification;

/** Persistence of notifications. */
public interface NotificationRepository {

    void insert(Notification notification);

    Optional<Notification> findById(UUID id);

    PageResult<Notification> listFor(UUID userId, PageQuery page);

    void update(Notification notification);
}
