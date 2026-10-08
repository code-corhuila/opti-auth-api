package co.edu.corhuila.opti.auth.adapter.out.persistence;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases.UserFilter;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.application.port.out.UserRepository;
import co.edu.corhuila.opti.auth.domain.model.DomainException;
import co.edu.corhuila.opti.auth.domain.model.Role;
import co.edu.corhuila.opti.auth.domain.model.User;

/** PostgreSQL implementation of {@link UserRepository}. The schema belongs to auth-db. */
public class JdbcUserRepository implements UserRepository {

    private static final String COLUMNS = """
            id, username, full_name, password_hash, role, active, failed_attempts, locked_until, sales_goal_cents,
            created_at, updated_at""";

    private final JdbcClient jdbc;

    public JdbcUserRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public void insert(User u) {
        try {
            jdbc.sql("INSERT INTO app_user (" + COLUMNS + ") VALUES (:id, :username, :fullName, :hash, :role,"
                            + " :active, :failed, :lockedUntil, :salesGoal, :createdAt, :updatedAt)")
                    .param("id", u.id()).param("username", u.username()).param("fullName", u.fullName())
                    .param("hash", u.passwordHash()).param("role", u.role().name()).param("active", u.active())
                    .param("failed", u.failedAttempts()).param("lockedUntil", Sql.ts(u.lockedUntil()))
                    .param("salesGoal", u.salesGoalCents()).param("createdAt", Sql.ts(u.createdAt()))
                    .param("updatedAt", Sql.ts(u.updatedAt()))
                    .update();
        } catch (DuplicateKeyException e) {
            throw DomainException.rule("the username is already taken");
        }
    }

    @Override
    public Optional<User> findById(UUID id) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM app_user WHERE id = :id")
                .param("id", id).query(JdbcUserRepository::map).optional();
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM app_user WHERE username = :username")
                .param("username", username).query(JdbcUserRepository::map).optional();
    }

    @Override
    public Optional<User> findByUsernameForUpdate(String username) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM app_user WHERE username = :username FOR UPDATE")
                .param("username", username).query(JdbcUserRepository::map).optional();
    }

    @Override
    public PageResult<User> search(UserFilter filter, PageQuery page) {
        List<String> conditions = new ArrayList<>();
        Map<String, Object> params = new HashMap<>();
        if (filter.query() != null && !filter.query().isBlank()) {
            conditions.add("(lower(username) LIKE :q OR lower(full_name) LIKE :q)");
            params.put("q", Sql.contains(filter.query()));
        }
        if (filter.role() != null) {
            conditions.add("role = :role");
            params.put("role", filter.role().name());
        }
        if (filter.active() != null) {
            conditions.add("active = :active");
            params.put("active", filter.active());
        }
        String where = conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions);

        long total = jdbc.sql("SELECT count(*) FROM app_user" + where).params(params).query(Long.class).single();
        List<User> rows = jdbc.sql("SELECT " + COLUMNS + " FROM app_user" + where
                        + " ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset")
                .params(params).param("limit", page.limit()).param("offset", page.offset())
                .query(JdbcUserRepository::map).list();
        return new PageResult<>(rows, page.page(), page.limit(), total);
    }

    @Override
    public void update(User u) {
        jdbc.sql("""
                UPDATE app_user SET password_hash = :hash, active = :active, failed_attempts = :failed,
                       locked_until = :lockedUntil, sales_goal_cents = :salesGoal, updated_at = :updatedAt
                WHERE id = :id
                """)
                .param("hash", u.passwordHash()).param("active", u.active()).param("failed", u.failedAttempts())
                .param("lockedUntil", Sql.ts(u.lockedUntil())).param("salesGoal", u.salesGoalCents())
                .param("updatedAt", Sql.ts(u.updatedAt())).param("id", u.id())
                .update();
    }

    private static User map(ResultSet rs, int row) throws SQLException {
        var locked = rs.getObject("locked_until", java.time.OffsetDateTime.class);
        return User.rehydrate(rs.getObject("id", UUID.class), rs.getString("username"), rs.getString("full_name"),
                rs.getString("password_hash"), Role.valueOf(rs.getString("role")), rs.getBoolean("active"),
                rs.getInt("failed_attempts"), locked == null ? null : locked.toInstant(),
                Sql.longOrNull(rs, "sales_goal_cents"), Sql.instant(rs, "created_at"), Sql.instant(rs, "updated_at"));
    }
}
