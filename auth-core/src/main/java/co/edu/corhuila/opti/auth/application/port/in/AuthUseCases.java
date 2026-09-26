package co.edu.corhuila.opti.auth.application.port.in;

import java.util.UUID;

import co.edu.corhuila.opti.auth.application.port.out.Created;
import co.edu.corhuila.opti.auth.domain.model.IssuedToken;
import co.edu.corhuila.opti.auth.domain.model.Role;
import co.edu.corhuila.opti.auth.domain.model.User;

/** What the identity service offers: sign-in, people management and service credentials. */
public interface AuthUseCases {

    /** Checks the credentials and issues an access token. Any failure answers the same "invalid credentials". */
    LoginResult login(String username, String password);

    User me(UUID userId);

    void changePassword(UUID userId, String currentPassword, String newPassword);

    Created<User> register(User.RegisterData data, String idempotencyKey);

    User get(UUID id);

    PageResult<User> search(UserFilter filter, PageQuery page);

    /** Deactivating yourself is refused: the last administrator could lock everyone out. */
    User setActive(UUID id, boolean active, UUID actorId);

    /** A long-lived token with the SERVICE role for the worker or the workflow. Shown once, never stored. */
    IssuedToken issueServiceToken(String name, Integer ttlDays);

    /** The token and the person it identifies. */
    record LoginResult(IssuedToken token, User user) {
    }

    /** Listing criteria; every field is optional. */
    record UserFilter(String query, Role role, Boolean active) {
    }
}
