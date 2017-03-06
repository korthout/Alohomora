package nl.nicokorthout.alohomora;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFilter;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;

import nl.nicokorthout.alohomora.auth.JWTAuthenticator;
import nl.nicokorthout.alohomora.auth.RoleAuthorizer;
import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.core.UserRegistration;
import nl.nicokorthout.alohomora.db.AdvertisementDAO;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.resources.AdvertisementResource;
import nl.nicokorthout.alohomora.resources.UserResource;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.skife.jdbi.v2.DBI;

import io.dropwizard.Application;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.jdbi.DBIFactory;
import io.dropwizard.jdbi.OptionalContainerFactory;
import io.dropwizard.jdbi.bundles.DBIExceptionsBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;

/**
 * This class represents the applications starting point. It sets-up the application and its
 * resources.
 */
public class Alohomora extends Application<AlohomoraConfiguration> {

    private DBIFactory dbiFactory;
    private DBI jdbi;
    private UserDAO userDAO;
    private AdvertisementDAO advertisementDAO;
    private byte[] jsonWebTokenSecret;
    private Encryption encryption;
    private UserRegistration userRegistration;
    private UserResource userResource;
    private AdvertisementResource advertisementResource;
    private AlohomoraConfiguration config;
    private Environment environment;

    public static void main(String[] args) throws Exception {
        new Alohomora().run(args);
    }

    @Override
    public void initialize(Bootstrap<AlohomoraConfiguration> bootstrap) {
        super.initialize(bootstrap);
        bootstrap.addBundle(new DBIExceptionsBundle());
    }

    @Override
    public void run(AlohomoraConfiguration config, Environment environment) throws Exception {
        this.config = config;
        this.environment = environment;
        setupDatabase();
        setupUtilities();
        setupDomainObjects(config);
        registerJWTAuthFilter(environment);
        setupResources(environment);
    }

    private void setupDatabase() {
        this.dbiFactory = new DBIFactory();
        this.jdbi = dbiFactory.build(environment, config.getDataSourceFactory(), "mysql");
        jdbi.registerContainerFactory(new OptionalContainerFactory());
        setupDAOs();
        createDBTables(userDAO);
    }

    private void setupDAOs() {
        this.userDAO = jdbi.onDemand(UserDAO.class);
        this.advertisementDAO = jdbi.onDemand(AdvertisementDAO.class);
    }

    private void createDBTables(UserDAO userDAO) {
        userDAO.createUserTableIfNotExists();
    }

    private void setupUtilities() {
        this.encryption = new Encryption();
    }

    private void setupDomainObjects(AlohomoraConfiguration config) {
        this.jsonWebTokenSecret = config.getJsonWebTokenSecret();
        this.userRegistration = new UserRegistration(userDAO, encryption);
    }

    private void registerJWTAuthFilter(Environment environment) {
        environment.jersey().register(new AuthDynamicFeature(
                new JWTAuthFilter.Builder<User>()
                        .setCookieName("jwt")
                        .setTokenParser(new DefaultJsonWebTokenParser())
                        .setTokenVerifier(new HmacSHA512Verifier(jsonWebTokenSecret))
                        .setRealm("SUPER SECRET STUFF")
                        .setPrefix("Bearer")
                        .setAuthenticator(new JWTAuthenticator(userDAO))
                        .setAuthorizer(new RoleAuthorizer())
                        .buildAuthFilter()));
        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(User.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
    }

    private void setupResources(Environment environment) {
        this.userResource = new UserResource(userDAO, encryption, jsonWebTokenSecret, userRegistration);
        this.advertisementResource = new AdvertisementResource(advertisementDAO);
        registerResources(environment);
    }

    private void registerResources(Environment environment) {
        environment.jersey().register(userResource);
        environment.jersey().register(advertisementResource);
    }

}
