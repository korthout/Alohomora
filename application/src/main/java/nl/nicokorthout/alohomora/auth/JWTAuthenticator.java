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
 */
public class JWTAuthenticator implements Authenticator<JsonWebToken, User> {

    private final UserDAO userDAO;

    public JWTAuthenticator(@NotNull UserDAO userDAO) {
        this.userDAO = Preconditions.checkNotNull(userDAO, "User DAO required");
    }

    @Override
    public Optional<User> authenticate(@NotNull JsonWebToken jsonWebToken) throws AuthenticationException {
        final JsonWebTokenValidator expiryValidator = new ExpiryValidator();
        expiryValidator.validate(jsonWebToken);
        return findUserFromToken(jsonWebToken);
    }

    private Optional<User> findUserFromToken(@NotNull JsonWebToken jsonWebToken) {
        java.util.Optional<User> user = userDAO.find(jsonWebToken.claim().subject());
        if (user.isPresent()) {
            return Optional.of(user.get());
        } else {
            return Optional.absent();
        }
    }

}
