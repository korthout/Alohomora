package nl.nicokorthout.alohomora.resources;

import com.google.common.base.Optional;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFilter;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;

import nl.nicokorthout.alohomora.api.NewAdvertisement;
import nl.nicokorthout.alohomora.auth.RoleAuthorizer;
import nl.nicokorthout.alohomora.core.Advertisement;
import nl.nicokorthout.alohomora.core.Role;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.AdvertisementDAO;

import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.time.LocalDate;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.testing.junit.ResourceTestRule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the Advertisement resource.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 27-12-2015
 */
public class AdvertisementResourceTest {

    private final Authenticator<JsonWebToken,User> authenticator = mock(Authenticator.class);
    private final AdvertisementDAO advertisementDAO = mock(AdvertisementDAO.class);

    private final byte[] jsonWebTokenSecret = "secret".getBytes();

    @Rule
    public final ResourceTestRule resources = ResourceTestRule.builder()
            .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
            .addProvider(new AuthDynamicFeature(new JWTAuthFilter.Builder<User>()
                    .setCookieName("jwt")
                    .setTokenParser(new DefaultJsonWebTokenParser())
                    .setTokenVerifier(new HmacSHA512Verifier(jsonWebTokenSecret))
                    .setAuthenticator(authenticator)
                    .setAuthorizer(new RoleAuthorizer())
                    .setRealm("SUPER SECRET STUFF")
                    .setPrefix("Bearer")
                    .buildAuthFilter()))
            .addProvider(RolesAllowedDynamicFeature.class)
            .addProvider(new AuthValueFactoryProvider.Binder<>(User.class))
            .addResource(new AdvertisementResource(advertisementDAO))
            .build();

    @Before
    public void setup() {
        reset(authenticator);
        reset(advertisementDAO);
    }

    @Test
    public void createAdvertisement() throws AuthenticationException {
        // Make sure the user is authenticated and authorized
        final User user = User.builder()
                .username("johndoe")
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .role(Role.PROVIDER.toString())
                .build();
        when(authenticator.authenticate(any(JsonWebToken.class))).thenReturn(Optional.of(user));

        // Make sure user can be found
        final HmacSHA512Signer signer = new HmacSHA512Signer(jsonWebTokenSecret);
        final JsonWebToken jsonWebToken = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder()
                        .subject(user.getUsername())
                        .issuedAt(DateTime.now())
                        .build())
                .build();
        final String signedToken = signer.sign(jsonWebToken);

        // Create the advertisement
        final NewAdvertisement advertisement = new NewAdvertisement("Some advertisement",
                "A description of this advertisement", "Some City", "Some Address 101", "1234AB");
        Response response = resources.getJerseyTest().target("/advertisements").request()
                .cookie("jwt", signedToken)
                .post(Entity.entity(advertisement, MediaType.APPLICATION_JSON));



        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.CREATED.getStatusCode());

        // Check advertisement stored
        verify(advertisementDAO).store(isA(Advertisement.class));
    }

    @Test
    public void createAdvertisementNotAuthenticated() throws AuthenticationException {
        // Make sure the user is not authenticated
        when(authenticator.authenticate(any(JsonWebToken.class))).thenReturn(Optional.absent());

        // Create the advertisement
        final NewAdvertisement advertisement = new NewAdvertisement("Some advertisement",
                "A description of this advertisement", "Some City", "Some Address 101", "1234AB");
        Response response = resources.getJerseyTest().target("/advertisements").request()
                .post(Entity.entity(advertisement, MediaType.APPLICATION_JSON));

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.UNAUTHORIZED.getStatusCode());
    }

    @Test
    public void createAdvertisementForbidden() throws AuthenticationException {
        // Make sure the user is authenticated, but not authorized
        final User user = User.builder()
                .username("johndoe")
                .registered(LocalDate.now())
                .email("johndoe@example.com")
                .role(Role.CUSTOMER.toString())
                .build();
        when(authenticator.authenticate(any(JsonWebToken.class))).thenReturn(Optional.of(user));

        // Make sure user can be found
        final HmacSHA512Signer signer = new HmacSHA512Signer(jsonWebTokenSecret);
        final JsonWebToken jsonWebToken = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(JsonWebTokenClaim.builder()
                        .subject(user.getUsername())
                        .issuedAt(DateTime.now())
                        .build())
                .build();
        final String signedToken = signer.sign(jsonWebToken);

        // Create the advertisement
        final NewAdvertisement advertisement = new NewAdvertisement("Some advertisement",
                "A description of this advertisement", "Some City", "Some Address 101", "1234AB");
        Response response = resources.getJerseyTest().target("/advertisements").request()
                .cookie("jwt", signedToken)
                .post(Entity.entity(advertisement, MediaType.APPLICATION_JSON));

        // Check response code
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
    }

}
