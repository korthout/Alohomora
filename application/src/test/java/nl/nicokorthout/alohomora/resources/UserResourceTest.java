package nl.nicokorthout.alohomora.resources;

import nl.nicokorthout.alohomora.api.NewUser;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.junit.Rule;
import org.junit.Test;

import java.util.Optional;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.dropwizard.jersey.validation.ValidationErrorMessage;
import io.dropwizard.testing.junit.ResourceTestRule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the User resource.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 22-12-2015
 */
public class UserResourceTest {

    private static final UserDAO dao = mock(UserDAO.class);

    @Rule
    public final ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(new UserResource(dao, new Encryption()))
            .build();

    @Test
    public void registerNewUser() {
        // Make sure username does not yet exists
        when(dao.find(eq("John Doe"))).thenReturn(Optional.empty());

        // Perform request to register user
        final NewUser newUser = new NewUser("John Doe", "mypassword123", "johndoe@example.com");
        Response response = resources.client().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 201 Created
        assertThat(response.getStatus()).isEqualTo(Response.Status.CREATED.getStatusCode());

        // Check username in response
        assertThat(response.readEntity(String.class)).isEqualTo("{\"username\":\"John Doe\"}");

        // Check location header in response
        assertThat(response.getLocation().toString())
                .isEqualTo("http://localhost:9998/application/users/me/token");

        // Check changes in database
        verify(dao).store(isA(User.class));
    }

    @Test
    public void registerNull() {
        // Perform request to register null user
        Response response = resources.client().target("/users").request()
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
        final NewUser newUser = new NewUser(null, null, null);

        // Perform request to register null user
        Response response = resources.client().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

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
        Response response = resources.client().target("/users").request()
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
        Response response = resources.client().target("/users").request()
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
                .username("John Doe")
                .build();
        when(dao.find(eq("John Doe"))).thenReturn(Optional.of(user));

        // Perform request to register null user
        final NewUser newUser = new NewUser("John Doe", "mypassword123", "johndoe@example.com");
        Response response = resources.client().target("/users").request()
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
        Response response = resources.client().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("name may not be admin");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

    @Test
    public void registerMe() {
        final NewUser newUser = new NewUser("me", "mypassword123", "johndoe@example.com");

        // Perform request to register null user
        Response response = resources.client().target("/users").request()
                .post(Entity.entity(newUser, MediaType.APPLICATION_JSON));

        // Check response is 422 Unprocessable Entity
        assertThat(response.getStatus()).isEqualTo(422);

        // Check errors are correct and human readable
        ValidationErrorMessage message = response.readEntity(ValidationErrorMessage.class);
        assertThat(message.getErrors()).containsOnly("name may not be me");

        // Check changes in database
        verify(dao, times(0)).store(isA(User.class));
    }

}
