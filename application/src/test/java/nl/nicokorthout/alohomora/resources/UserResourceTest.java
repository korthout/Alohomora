package nl.nicokorthout.alohomora.resources;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFilter;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;

import nl.nicokorthout.alohomora.api.NewUser;
import nl.nicokorthout.alohomora.auth.JWTAuthenticator;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.glassfish.jersey.internal.util.Base64;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.time.LocalDate;
import java.util.Map;
import java.util.Optional;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;

import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.jersey.validation.ValidationErrorMessage;
import io.dropwizard.testing.junit.ResourceTestRule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the User resource.
 *
 * @author Nico Korthout
 * @version 0.3.0
 * @since 22-12-2015
 */
public class UserResourceTest {

    private static final UserDAO dao = mock(UserDAO.class);

    private final byte[] jsonWebTokenSecret = "secret".getBytes();

    @Rule
    public final ResourceTestRule resources = ResourceTestRule.builder()
            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
            .addProvider(new AuthDynamicFeature(new JWTAuthFilter.Builder<User>()
                    .setCookieName("jwt")
                    .setTokenParser(new DefaultJsonWebTokenParser())
                    .setTokenVerifier(new HmacSHA512Verifier(jsonWebTokenSecret))
                    .setAuthenticator(new JWTAuthenticator(dao))
                    .setRealm("SUPER SECRET STUFF")
                    .setPrefix("Bearer")
                    .buildAuthFilter()))
            .addProvider(RolesAllowedDynamicFeature.class)
            .addProvider(new AuthValueFactoryProvider.Binder<>(User.class))
            .addResource(new UserResource(dao, new Encryption(), jsonWebTokenSecret))
            .build();

    @Before
    public void setup() {
        reset(dao);
    }

    @Test
    public void registerNewUser() {
        // Make sure username does not yet exists
        when(dao.find(eq("johndoe"))).thenReturn(Optional.empty());

        // Perform request to register user
        final NewUser newUser = new NewUser("johndoe", "mypassword123", "johndoe@example.com");
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 201 Created
        assertThat(response.getStatus()).isEqualTo(Response.Status.CREATED.getStatusCode());

        // Check username in response
        assertThat(response.readEntity(String.class)).isEqualTo("{\"username\":\"johndoe\"}");

        // Check location header in response
        assertThat(response.getLocation().toString())
                .isEqualTo("http://localhost:9998/users/me/token");

        // Check changes in database
        verify(dao).store(isA(User.class));
    }

    @Test
    public void registerNull() {
        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(null, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("The request entity was empty");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerValuesNull() {
        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity("{}", MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).contains("username may not be null",
                "password may not be null", "email may not be null");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerValuesTooShort() {
        final NewUser newUser = new NewUser("", "pa", "");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).contains("username size must be between 1 and 20",
                "password size must be between 3 and 2147483647",
                "email size must be between 1 and 254");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerUsernameTooShort() {
        final NewUser newUser = new NewUser("thisisareallylongusername", "mypassword123",
                "johndoe@example.com");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("username size must be between 1 and 20");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerConflict() {
        // Make sure username does already exists
        User user = User.builder()
                .username("johndoe")
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .salt("salt".getBytes())
                .password("password".getBytes())
                .build();
        when(dao.find(eq("johndoe"))).thenReturn(Optional.of(user));

        // Perform request to register null user
        final NewUser newUser = new NewUser("johndoe", "mypassword123", "johndoe@example.com");
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 409 Conflict
        assertThat(response.getStatus()).isEqualTo(Response.Status.CONFLICT.getStatusCode());

        // Check errors are correct and human readable
        assertThat(response.readEntity(String.class)).isEqualTo("username unavailable");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerAdmin() {
        final NewUser newUser = new NewUser("admin", "mypassword123", "johndoe@example.com");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("username may not be admin");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerMe() {
        final NewUser newUser = new NewUser("me", "mypassword123", "johndoe@example.com");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("username may not be me");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerNonAlphanumeric() {
        final NewUser newUser = new NewUser("iam!@#$%^", "mypassword123", "johndoe@example.com");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("username must be alphanumeric");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void loginUser() {
        final String username = "johndoe";
        final String password = "mypassword123";
        final byte[] salt = "somesalt".getBytes();
        final byte[] hashedPassword = new Encryption().hashPassword(password, salt);

        User user = User.builder()
                .username(username)
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Make sure one user exists
        when(dao.find(username)).thenReturn(Optional.of(user));

        // Encode the user's credentials using Base64
        String authorization = "Basic " + Base64.encodeAsString(username + ":" + password);

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        // Check token cookie in the response
        Map<String, NewCookie> cookies = response.getCookies();
        NewCookie token = cookies.get("jwt");
        assertThat(token.getValue()).isNotEmpty();
        assertThat(token.isHttpOnly()).isTrue();
    }

    @Test
    public void loginUnknownUser() {
        // Encode the user's credentials using Base64
        String authorization = "Basic " + Base64.encodeAsString("johndoe:mypassword123");

        when(dao.find(any(String.class))).thenReturn(Optional.empty());

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());

        // Check no cookie was set
        assertThat(response.getCookies()).isEmpty();
    }

    @Test
    public void loginWrongPassword() {
        final String username = "johndoe";
        final String password = "mypassword123";
        final byte[] salt = "somesalt".getBytes();
        final byte[] hashedPassword = new Encryption().hashPassword(password, salt);

        User user = User.builder()
                .username(username)
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Make sure one user exists
        when(dao.find(username)).thenReturn(Optional.of(user));

        // Encode the user's credentials using Base64
        String authorization = "Basic " + Base64.encodeAsString(username + ":wrongpassword");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());

        // Check no cookie was set
        assertThat(response.getCookies()).isEmpty();
    }

    @Test
    public void loginNoAuthHeader() {
        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.BAD_REQUEST.getStatusCode());

        // Check no cookie was set
        assertThat(response.getCookies()).isEmpty();
    }

    @Test
    public void loginAuthHeaderNotBasic() {
        // Encode the user's credentials using Base64
        String authorization = "NotBasic " + Base64.encodeAsString("johndoe:mypassword123");

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());

        // Check no cookie was set
        assertThat(response.getCookies()).isEmpty();
    }

    @Test
    public void loginIgnoreCaseUsernameUpperCase() {
        final String username = "johndoe";
        final String password = "mypassword123";
        final byte[] salt = "somesalt".getBytes();
        final byte[] hashedPassword = new Encryption().hashPassword(password, salt);

        User user = User.builder()
                .username(username.toLowerCase())
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Make sure one user exists
        when(dao.find(username.toUpperCase())).thenReturn(Optional.of(user));

        // Encode the user's credentials using Base64
        String authorization = "Basic " +
                Base64.encodeAsString(username.toUpperCase() + ":" + password);

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        // Check token cookie in the response
        Map<String, NewCookie> cookies = response.getCookies();
        NewCookie token = cookies.get("jwt");
        assertThat(token.getValue()).isNotEmpty();
        assertThat(token.isHttpOnly()).isTrue();
    }

    @Test
    public void loginIgnoreCaseUsernameLowerCase() {
        final String username = "johndoe";
        final String password = "mypassword123";
        final byte[] salt = "somesalt".getBytes();
        final byte[] hashedPassword = new Encryption().hashPassword(password, salt);

        User user = User.builder()
                .username(username.toUpperCase())
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Make sure one user exists
        when(dao.find(username.toLowerCase())).thenReturn(Optional.of(user));

        // Encode the user's credentials using Base64
        String authorization = "Basic " +
                Base64.encodeAsString(username.toLowerCase() + ":" + password);

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        // Check token cookie in the response
        Map<String, NewCookie> cookies = response.getCookies();
        NewCookie token = cookies.get("jwt");
        assertThat(token.getValue()).isNotEmpty();
        assertThat(token.isHttpOnly()).isTrue();
    }

    @Test
    public void loginCaseSensitivePassword() {
        final String username = "johndoe";
        final String password = "mypassword123";
        final byte[] salt = "somesalt".getBytes();
        final byte[] hashedPassword = new Encryption().hashPassword(password, salt);

        User user = User.builder()
                .username(username)
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Make sure one user exists
        when(dao.find(username)).thenReturn(Optional.of(user));

        // Encode the user's credentials using Base64
        String authorization = "Basic " +
                Base64.encodeAsString(username + ":" + password.toUpperCase());

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());

        // Check no cookie was set
        assertThat(response.getCookies()).isEmpty();
    }

    @Test
    public void loginByEmail() {
        final String username = "johndoe";
        final String password = "mypassword123";
        final byte[] salt = "somesalt".getBytes();
        final byte[] hashedPassword = new Encryption().hashPassword(password, salt);
        final String email = "johndoe@example.com";

        User user = User.builder()
                .username(username)
                .registered(LocalDate.now())
                .email(email)
                .salt(salt)
                .password(hashedPassword)
                .build();

        // Make sure one user exists
        when(dao.findByEmail(email)).thenReturn(Optional.of(user));

        // Encode the user's credentials using Base64
        String authorization = "Basic " + Base64.encodeAsString(email + ":" + password);

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me/token").request()
                .header(HttpHeaders.AUTHORIZATION, authorization)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        // Check token cookie in the response
        Map<String, NewCookie> cookies = response.getCookies();
        NewCookie token = cookies.get("jwt");
        assertThat(token.getValue()).isNotEmpty();
        assertThat(token.isHttpOnly()).isTrue();
    }

    @Test
    public void getMe() {
        // Make sure one user exists
        final String username = "johndoe";
        User user = User.builder()
                .username(username)
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .build();
        when(dao.find(username)).thenReturn(Optional.of(user));

        // Make sure user can be found
        final HmacSHA512Signer signer = new HmacSHA512Signer(jsonWebTokenSecret);
        final JsonWebToken jsonWebToken = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder()
                        .subject(username)
                        .issuedAt(DateTime.now())
                        .build())
                .build();
        final String signedToken = signer.sign(jsonWebToken);

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me").request()
                .cookie("jwt", signedToken)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        // Check response entity
        assertThat(response.readEntity(User.class)).isEqualTo(user);
    }

    @Test
    public void getMeUnauthorized() {
        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me").request()
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());

        // Check error is correct and human readable
        assertThat(response.readEntity(String.class))
                .isEqualTo("Credentials are required to access this resource.");
    }

    @Test
    public void getMeUserDoesNotExist() {
        // Make sure no user exists
        when(dao.find(any(String.class))).thenReturn(Optional.empty());

        // Make sure user can be found
        final HmacSHA512Signer signer = new HmacSHA512Signer(jsonWebTokenSecret);
        final JsonWebToken jsonWebToken = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder()
                        .subject("johndoe")
                        .issuedAt(DateTime.now())
                        .build())
                .build();
        final String signedToken = signer.sign(jsonWebToken);

        // Perform request to register null user
        Response response = resources.getJerseyTest().target("/users/me").request()
                .cookie("jwt", signedToken)
                .get();

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());

        // Check error is correct and human readable
        assertThat(response.readEntity(String.class))
                .isEqualTo("Credentials are required to access this resource.");
    }

}
