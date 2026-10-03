package co.edu.corhuila.opti.auth.adapter.out.persistence;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;

import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.application.port.out.NotificationRepository;
import co.edu.corhuila.opti.auth.domain.model.Notification;
import co.edu.corhuila.opti.auth.domain.model.NotificationType;

/** PostgreSQL implementation of {@link NotificationRepository}. The schema belongs to auth-db. */
public class JdbcNotificationRepository implements NotificationRepository {

    private static final String COLUMNS = "id, user_id, type, message, read_at, created_at";

    private final JdbcClient jdbc;

    public JdbcNotificationRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void insert(Notification n) {
        jdbc.sql("INSERT INTO notification (" + COLUMNS + ") VALUES (:id, :userId, :type, :message, :readAt,"
                        + " :createdAt)")
                .param("id", n.id()).param("userId", n.userId()).param("type", n.type().name())
                .param("message", n.message()).param("readAt", Sql.ts(n.readAt()))
                .param("createdAt", Sql.ts(n.createdAt()))
                .update();
    }

    @Override
    public Optional<Notification> findById(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM notification WHERE id = :id")
                .param("id", id).query(JdbcNotificationRepository::map).optional();
    }

    @Override
    public PageResult<Notification> listFor(UUID userId, PageQuery page) {
        long total = jdbc.sql("SELECT count(*) FROM notification WHERE user_id = :userId")
                .param("userId", userId).query(Long.class).single();
        List<Notification> rows = jdbc.sql("SELECT " + COLUMNS + " FROM notification WHERE user_id = :userId"
                        + " ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset")
                .param("userId", userId).param("limit", page.limit()).param("offset", page.offset())
                .query(JdbcNotificationRepository::map).list();
        return new PageResult<>(rows, page.page(), page.limit(), total);
    }

    @Override
    public void update(Notification n) {
        jdbc.sql("UPDATE notification SET read_at = :readAt WHERE id = :id")
                .param("readAt", Sql.ts(n.readAt())).param("id", n.id())
                .update();
    }

    private static Notification map(ResultSet rs, int row) throws SQLException {
        var readAt = rs.getObject("read_at", java.time.OffsetDateTime.class);
        return Notification.rehydrate(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class),
                NotificationType.valueOf(rs.getString("type")), rs.getString("message"),
                readAt == null ? null : readAt.toInstant(), Sql.instant(rs, "created_at"));
    }
}
