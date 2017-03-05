package nl.nicokorthout.alohomora.api;

import org.junit.Test;

import io.dropwizard.jackson.Jackson;

import static io.dropwizard.testing.FixtureHelpers.fixture;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by nicokorthout on 27/12/15.
 */
public class NewAdvertisementTest {

    @Test
    public void serializeToJSON() throws Exception {
        assertThat(Jackson.newObjectMapper().writerWithDefaultPrettyPrinter()
                .writeValueAsString(new NewAdvertisement("Some advertisement",
                        "A description of this advertisement",
                        "Enschede",
                        "Calslaan 3-209",
                        "7522MH")))
                .isEqualTo(fixture("fixtures/newadvertisement.json"));
    }


    @Test
    public void deserializeFromJSON() throws Exception {
        assertThat(Jackson.newObjectMapper()
                .readValue(fixture("fixtures/newadvertisement.json"), NewAdvertisement.class))
                .isEqualTo(new NewAdvertisement("Some advertisement",
                        "A description of this advertisement",
                        "Enschede",
                        "Calslaan 3-209",
                        "7522MH"));
    }

}
