package nl.nicokorthout.alohomora.resources;

import com.google.common.base.Preconditions;

import nl.nicokorthout.alohomora.api.NewUser;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.LocalDate;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

/**
 * The user resource provides access to user functions for clients.
 *
 * @author Nico Korthout
 * @version 0.2.0
 * @since 06-12-2015
 */
@Path("/users")
public class UserResource {

    private final Logger logger = LoggerFactory.getLogger(UserResource.class);

    private final UserDAO userDAO;
    private final Encryption encryption;

    /**
     * Constructor for the user resource.
     *
     * @param userDAO A User DAO.
     * @param encryption The Encryption that will be used for password hashing.
     */
    public UserResource(@NotNull UserDAO userDAO, @NotNull Encryption encryption) {
        this.userDAO = Preconditions.checkNotNull(userDAO, "User DAO is not set");
        this.encryption = Preconditions.checkNotNull(encryption, "Encryption is not set");
    }

    /**
     * Register a new user.
     *
     * @param newUser The new user to register.
     * @return 201 Response if successful, 4XX Response if not.
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(@Valid NewUser newUser) {
        // Check username available
        if (userDAO.find(newUser.getUsername()).isPresent()) {
            return Response.status(Response.Status.CONFLICT).entity("username unavailable").build();
        }

        // Hash Password
        byte[] salt = encryption.generateSalt();
        byte[] hashedPassword = encryption.hashPassword(newUser.getPassword(), salt);

        // Create a User from the NewUser
        User user = User.builder().username(newUser.getUsername())
                .registered(LocalDate.now())
                .email(newUser.getEmail())
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Register user
        userDAO.store(user);
        logger.info("Registered user '{}'", user.getUsername());

        // Respond: 201 Created with location header pointing to login URI
        URI location = UriBuilder.fromResource(UserResource.class).build();
        return Response.created(location)
                .entity("{\"username\":\"" + user.getUsername() + "\"}")
                .build();
    }

}
