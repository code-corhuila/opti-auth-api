package co.edu.corhuila.opti.auth.testsupport;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.application.port.out.NotificationRepository;
import co.edu.corhuila.opti.auth.domain.model.Notification;

/** In-memory fake of the notification store, used to test the core and the HTTP adapter without a database. */
public final class InMemoryNotifications implements NotificationRepository {

    private final Map<UUID, Notification> byId = new HashMap<>();

    @Override
    public void insert(Notification notification) {
        byId.put(notification.id(), notification);
    }

    @Override
    public Optional<Notification> findById(UUID id) {
        return Optional.ofNullable(byId.get(id));
    }

    @Override
    public PageResult<Notification> listFor(UUID userId, PageQuery page) {
        List<Notification> mine = byId.values().stream().filter(n -> n.userId().equals(userId))
                .sorted(Comparator.comparing(Notification::createdAt).reversed().thenComparing(Notification::id))
                .toList();
        int from = Math.min(page.offset(), mine.size());
        int to = Math.min(from + page.limit(), mine.size());
        return new PageResult<>(mine.subList(from, to), page.page(), page.limit(), mine.size());
    }

    @Override
    public void update(Notification notification) {
        byId.put(notification.id(), notification);
    }
}
