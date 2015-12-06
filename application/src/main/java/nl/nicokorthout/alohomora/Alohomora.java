package nl.nicokorthout.alohomora;

import nl.nicokorthout.alohomora.resources.UserResource;

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
    public void run(AlohomoraConfiguration configuration, Environment environment) {
        environment.jersey().register(new UserResource());
    }

}
