package nl.nicokorthout.alohomora.resources;

import com.google.common.base.Preconditions;

import nl.nicokorthout.alohomora.db.UserDAO;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Path;

/**
 * The user resource provides access to user functions for clients.
 *
 * @author Nico Korthout
 * @version 0.1.1
 * @since 06-12-2015
 */
@Path("/users")
public class UserResource {

    private final UserDAO userDAO;

    public UserResource(@NotNull UserDAO userDAO) {
        this.userDAO = Preconditions.checkNotNull(userDAO, "userDao is not set");
        this.userDAO.createUserTable();
    }

}
