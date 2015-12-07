package nl.nicokorthout.alohomora;

import com.mongodb.DB;
import com.mongodb.Mongo;

import nl.nicokorthout.alohomora.db.MongoHealthCheck;
import nl.nicokorthout.alohomora.db.MongoManaged;
import nl.nicokorthout.alohomora.resources.UserResource;

import java.net.UnknownHostException;

import io.dropwizard.Application;
import io.dropwizard.setup.Environment;

/**
 * Created by nicokorthout on 06/12/15.
 */
public class Alohomora extends Application<AlohomoraConfiguration> {

    public static void main(String[] args) throws Exception {
        new Alohomora().run(args);
    }

    @Override
    public void run(AlohomoraConfiguration configuration, Environment environment)
            throws UnknownHostException {

        // Setup Mongo
        Mongo mongo = new Mongo(configuration.getMongohost(), configuration.getMongoport());
        MongoManaged mongoManaged = new MongoManaged(mongo);
        environment.lifecycle().manage(mongoManaged);
        environment.healthChecks().register("mongodb", new MongoHealthCheck(mongo));
        DB database = mongo.getDB(configuration.getMongodb());

        // Register resources
        environment.jersey().register(new UserResource(database));
    }

}
