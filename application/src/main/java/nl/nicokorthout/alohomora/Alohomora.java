package nl.nicokorthout.alohomora;

import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.resources.UserResource;

import org.skife.jdbi.v2.DBI;

import io.dropwizard.Application;
import io.dropwizard.jdbi.DBIFactory;
import io.dropwizard.setup.Environment;

/**
 * This class represents the applications starting point.
 * It sets-up the application and its resources.
 *
 * @author Nico Korthout
 * @version 0.1.1
 * @since 06-12-2015
 */
public class Alohomora extends Application<AlohomoraConfiguration> {

    public static void main(String[] args) throws Exception {
        new Alohomora().run(args);
    }

    @Override
    public void run(AlohomoraConfiguration config, Environment environment) {

        final DBIFactory factory = new DBIFactory();
        final DBI jdbi = factory.build(environment, config.getDataSourceFactory(), "mysql");
        final UserDAO userDAO = jdbi.onDemand(UserDAO.class);

        // Register resources
        environment.jersey().register(new UserResource(userDAO));
    }

}
