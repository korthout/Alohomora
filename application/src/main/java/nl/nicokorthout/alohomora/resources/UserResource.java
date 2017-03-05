package nl.nicokorthout.alohomora.resources;

import com.google.common.base.Preconditions;

import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;

import nl.nicokorthout.alohomora.api.NewUser;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.core.UserRegistration;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.apache.commons.validator.routines.EmailValidator;
import org.glassfish.jersey.internal.util.Base64;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotEmpty;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.Charset;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Optional;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import io.dropwizard.auth.Auth;

/**
 * The user resource provides access to user functions like registration and login as a REST-ful API.
 */
@Path("/users")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class UserResource {

    private final Logger logger = LoggerFactory.getLogger(UserResource.class);
    private final UserDAO userDAO;
    private final Encryption encryption;
    private final byte[] jsonWebTokenSecret;
    private final UserRegistration userRegistration;

    public UserResource(@NotNull UserDAO userDAO, @NotNull Encryption encryption,
                        @NotNull byte[] jsonWebTokenSecret, @NotNull UserRegistration userRegistration) {
        this.userDAO = Preconditions.checkNotNull(userDAO, "UserDAO is not set");
        this.encryption = Preconditions.checkNotNull(encryption, "Encryption is not set");
        this.jsonWebTokenSecret = Preconditions.checkNotNull(jsonWebTokenSecret, "JWT Secret is not set");
        this.userRegistration = Preconditions.checkNotNull(userRegistration, "UserRegistration is not set");
    }

    /**
     * Register a new user.
     * @return 201 Created Response if successful, 4XX Response if not.
     */
    @POST
    public Response register(@NotNull @Valid NewUser newUser, @Context UriInfo uriInfo) {
        if (!userRegistration.checkUsernameAvailable(newUser))
            return getResponseUsernameTaken();

        if (!userRegistration.checkEmailAvailable(newUser))
            return getResponseEmailTaken();

        User user = userRegistration.registerUser(newUser);
        return getCreatedResponse(uriInfo, user);
    }

    private Response getResponseUsernameTaken() {
        return Response.status(Response.Status.CONFLICT)
                .entity("username already in use")
                .build();
    }

    private Response getResponseEmailTaken() {
        return Response.status(Response.Status.CONFLICT)
                .entity("email already in use")
                .build();
    }

    /**
     * @return 201 Created Response with the location header pointing to the user login URI
     */
    private Response getCreatedResponse(@NotNull UriInfo uriInfo, @NotNull User user) {
        URI location = uriInfo.getBaseUriBuilder()
                .path("users/me/token")
                .build();
        return Response.created(location)
                .entity("{\"username\":\"" + user.getUsername() + "\"}")
                .build();
    }

    /**
     * Login a user.
     *
     * @param authorization Basic authorization header (Basic base64EncodedCredentials).
     * @return 200 OK with jwt cookie for later authentication or 401 Unauthorized.
     */
    @Path("me/token")
    @GET
    public Response login(@HeaderParam(HttpHeaders.AUTHORIZATION) @NotEmpty String authorization) {
        if (authorization.startsWith("Basic")) {

            // Authorization: Basic base64EncodedCredentials
            final String base64EncodedCredentials = authorization.substring("Basic".length()).trim();
            final String credentials = new String(
                    Base64.decode(base64EncodedCredentials.getBytes()), Charset.forName("UTF-8"));

            // Credentials = identifier:password (where identifier = username or email)
            final String[] values = credentials.split(":", 2);
            if (values.length == 2) {
                final String identifier = values[0];
                final String password = values[1];

                // Get existing User from Database using identifier or email
                Optional<User> existingUser;
                if (EmailValidator.getInstance().isValid(identifier)) {
                    existingUser = userDAO.findByEmail(identifier);
                } else {
                    existingUser = userDAO.find(identifier);
                }

                if (existingUser.isPresent()) {

                    // hash Password of User
                    final byte[] salt = existingUser.get().getSalt();
                    final byte[] hashedPassword = encryption.hashPassword(password, salt);

                    // Check hashedPasswords match
                    if (Arrays.equals(hashedPassword, existingUser.get().getPassword())) {

                        final HmacSHA512Signer signer = new HmacSHA512Signer(jsonWebTokenSecret);
                        final JsonWebToken jsonWebToken = JsonWebToken.builder()
                                .header(JsonWebTokenHeader.HS512())
                                .claim(JsonWebTokenClaim.builder()
                                        .subject(existingUser.get().getUsername())
                                        .issuedAt(DateTime.now())
                                        .build())
                                .build();
                        final String signedToken = signer.sign(jsonWebToken);

                        int maxAge = NewCookie.DEFAULT_MAX_AGE;
                        maxAge = 1 * 60; // TODO: set back to max age

                        // Create an HttpOnly Cookie for the authentication jsonWebToken
                        final Cookie tokenCookie = new Cookie("jwt", signedToken);
                        final NewCookie cookie =
                                new NewCookie(tokenCookie, "", maxAge, null, false, true);

                        // Respond with the jsonWebToken
                        return Response.ok()
                                .cookie(cookie)
                                .entity("logged in user " + existingUser.get().getUsername())
                                .build();
                    }
                }
            }
        }

        // 401 Unauthorized
        logger.info("Didn't login user, credentials could not be authenticated");
        return Response.status(Response.Status.UNAUTHORIZED)
                /*
                 * if you send these www-authenticate headers
                 * it will result in the browser showing the standard login popup window
                 * but these are required by the RFC, so I commented them for possible later use
                 * .header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"/api/*\" location=\"/api/users/me/token\"")
                 * .header(HttpHeaders.WWW_AUTHENTICATE, "token realm=\"/api/*\" location=\"/api/*\"")
                 */
                .build();
    }

    /**
     * Retrieve information about the logged in user.
     *
     * @param user The logged in user (provided by Dropwizard's auth).
     * @return The logged in user.
     */
    @Path("me")
    @GET
    public User getMe(@Auth User user) {
        return user;
    }

    /**
     * Change the password of the logged in user.
     *
     * @param user The logged in user (provided by Dropwizard's auth).
     * @param password The new (unhashed) password for the user.
     * @return 200 OK if updated correctly.
     */
    @Path("me/password")
    @PUT
    public Response changePassword(@Auth User user, @NotNull @Length(min = 3) String password) {
        final byte[] salt = encryption.generateSalt();
        final byte[] hashedPassword = encryption.hashPassword(password, salt);
        userDAO.update(user.asBuilder().password(hashedPassword).salt(salt).build());
        return Response.ok().build();
    }

}
