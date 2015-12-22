package nl.nicokorthout.alohomora.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

import org.junit.Test;

import io.dropwizard.jackson.Jackson;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests to check (de)serialization of JSON to NewUser.
 * Does not include validation checking, which is tested in UserResourceTest.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 22-12-2015
 */
public class NewUserTest {

    @Test
    public void serializeToJSON() throws Exception {
        final NewUser newUser = new NewUser("John Doe", "mypassword123", "johndoe@example.com");
        final ObjectWriter writer = Jackson.newObjectMapper().writerWithDefaultPrettyPrinter();

        assertThat(writer.writeValueAsString(newUser)).isEqualTo(fixture("fixtures/newuser.json"));
    }


    @Test
    public void deserializeFromJSON() throws Exception {
        final NewUser newUser = new NewUser("John Doe", "mypassword123", "johndoe@example.com");
        final ObjectMapper mapper = Jackson.newObjectMapper();

        assertThat(mapper.readValue(fixture("fixtures/newuser.json"), NewUser.class))
                .isEqualTo(newUser);
    }

}
