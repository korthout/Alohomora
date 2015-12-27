package nl.nicokorthout.alohomora.auth;

import nl.nicokorthout.alohomora.core.User;

import io.dropwizard.auth.Authorizer;

/**
 * Checks if a user principal is authorized for a specific role.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 27-12-2015
 */
public class RoleAuthorizer implements Authorizer<User> {

    @Override
    public boolean authorize(User user, String role) {
        return role.equalsIgnoreCase(user.getRole());
    }

}
