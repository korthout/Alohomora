package nl.nicokorthout.alohomora.auth;

import nl.nicokorthout.alohomora.core.User;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.dropwizard.auth.Authorizer;

/**
 * Checks if a user principal is authorized for a specific role.
 */
public class RoleAuthorizer implements Authorizer<User> {

    private final Logger logger = LoggerFactory.getLogger(RoleAuthorizer.class);

    @Override
    public boolean authorize(final User user, final String role) {
        logger.debug("authorizing user {}", user.getName());
        return role.equalsIgnoreCase(user.getRole());
    }

}
