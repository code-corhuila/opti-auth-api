package co.edu.corhuila.opti.auth.application.port.out;

import java.util.Optional;
import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.in.AuthUseCases.UserFilter;
import co.edu.corhuila.opti.auth.application.port.in.PageQuery;
import co.edu.corhuila.opti.auth.application.port.in.PageResult;
import co.edu.corhuila.opti.auth.domain.model.User;

/** Persistence of users. */
public interface UserRepository {

    /** Stores the user; a username already taken is a business rule violation. */
    void insert(User user);

    Optional<User> findById(UUID id);

    Optional<User> findByUsername(String username);

    /** Reads the user locking its row, so concurrent failed sign-ins count one by one. */
    Optional<User> findByUsernameForUpdate(String username);

    PageResult<User> search(UserFilter filter, PageQuery page);

    /** Persists the mutable part of the user: password hash, state, lock and update time. */
    void update(User user);
}
