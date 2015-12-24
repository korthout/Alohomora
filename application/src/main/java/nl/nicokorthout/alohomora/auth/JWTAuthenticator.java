package nl.nicokorthout.alohomora.auth;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenValidator;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.validator.ExpiryValidator;

import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.UserDAO;

import javax.validation.constraints.NotNull;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;

/**
 * Authenticates a user using a JSON Web Token (JWT).
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 22-12-2015
 */
public class JWTAuthenticator implements Authenticator<JsonWebToken, User> {

    private final UserDAO userDAO;

    public JWTAuthenticator(@NotNull UserDAO userDAO) {
        this.userDAO = Preconditions.checkNotNull(userDAO, "User DAO required");
    }

    @Override
    public Optional<User> authenticate(JsonWebToken jsonWebToken) throws AuthenticationException {
        final JsonWebTokenValidator expiryValidator = new ExpiryValidator();

        // Provide your own implementation to lookup users based on the principal attribute in the
        // JWT Token. E.g.: lookup users from a database etc.
        // This method will be called once the token's signature has been verified

        // In case you want to verify different parts of the token you can do that here.
        // E.g.: Verifying that the provided token has not expired.

        // All JsonWebTokenExceptions will result in a 401 Unauthorized response.

        // Validate expiration date of the token
        expiryValidator.validate(jsonWebToken);

        // Return the User that belongs to this claim
        java.util.Optional<User> user = userDAO.find(jsonWebToken.claim().subject());
        if (user.isPresent()) {
            return Optional.of(user.get());
        } else {
            return Optional.absent();
        }
    }

}
