package nl.nicokorthout.alohomora.api;

import nl.nicokorthout.alohomora.core.Role;

import org.junit.Test;

import io.dropwizard.jackson.Jackson;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests to check (de)serialization of JSON to NewUser.
 * Does not include validation checking, which is tested in UserResourceTest.
 *
 * @author Nico Korthout
 * @version 0.1.1
 * @since 22-12-2015
 */
public class NewUserTest {

    @Test
    public void serializeToJSON() throws Exception {
        assertThat(Jackson.newObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(new NewUser("JohnDoe", "mypassword123", "johndoe@example.com",
                        Role.CUSTOMER.toString()))).isEqualTo(fixture("fixtures/newuser.json"));
    }


    @Test
    public void deserializeFromJSON() throws Exception {
        assertThat(Jackson.newObjectMapper()
                .readValue(fixture("fixtures/newuser.json"), NewUser.class))
                .isEqualTo(new NewUser("JohnDoe", "mypassword123", "johndoe@example.com",
                        Role.CUSTOMER.toString()));
    }

}
