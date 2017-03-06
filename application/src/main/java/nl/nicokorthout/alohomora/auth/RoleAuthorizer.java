package nl.nicokorthout.alohomora.auth;

import nl.nicokorthout.alohomora.core.User;

import io.dropwizard.auth.Authorizer;

/**
 * Checks if a user principal is authorized for a specific role.
 */
public class RoleAuthorizer implements Authorizer<User> {

    @Override
    public boolean authorize(final User user, final String role) {
        System.out.println("authorizing user " + user.getName());
        return role.equalsIgnoreCase(user.getRole());
    }

}
