package nl.nicokorthout.alohomora;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFilter;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;

import nl.nicokorthout.alohomora.auth.JWTAuthenticator;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.resources.UserResource;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.skife.jdbi.v2.DBI;

import io.dropwizard.Application;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.java8.Java8Bundle;
import io.dropwizard.java8.jdbi.DBIFactory;
import io.dropwizard.java8.jdbi.OptionalContainerFactory;
import io.dropwizard.jdbi.bundles.DBIExceptionsBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

/**
 * This class represents the applications starting point. It sets-up the application and its
 * resources.
 *
 * @author Nico Korthout
 * @version 0.2.1
 * @since 06-12-2015
 */
public class Alohomora extends Application<AlohomoraConfiguration> {

    public static void main(String[] args) throws Exception {
        new Alohomora().run(args);
    }

    @Override
    public void initialize(Bootstrap<AlohomoraConfiguration> bootstrap) {
        super.initialize(bootstrap);
        bootstrap.addBundle(new DBIExceptionsBundle());
        bootstrap.addBundle(new Java8Bundle());
    }

    @Override
    public void run(AlohomoraConfiguration config, Environment environment) throws Exception {

        // Setup the database connection
        final DBIFactory factory = new DBIFactory();
        final DBI jdbi = factory.build(environment, config.getDataSourceFactory(), "mysql");
        jdbi.registerContainerFactory(new OptionalContainerFactory());

        // Create the DAOs
        final UserDAO userDAO = jdbi.onDemand(UserDAO.class);

        // Create the tables, if they don't yet exists
        userDAO.createUserTable();

        // Setup the JWT Auth Filter
        final byte[] jsonWebTokenSecret = config.getJsonWebTokenSecret();
        final JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
        final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(jsonWebTokenSecret);
        final JWTAuthenticator authenticator = new JWTAuthenticator(userDAO);
        environment.jersey().register(new AuthDynamicFeature(
                new JWTAuthFilter.Builder<User>()
                        .setCookieName("jwt")
                        .setTokenParser(tokenParser)
                        .setTokenVerifier(tokenVerifier)
                        .setRealm("SUPER SECRET STUFF")
                        .setPrefix("Bearer")
                        .setAuthenticator(authenticator)
                        .buildAuthFilter()));
        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(User.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);

        // Setup utilities
        final Encryption encryption = new Encryption();

        // Register resources
        environment.jersey().register(new UserResource(userDAO, encryption, jsonWebTokenSecret));
    }

}
