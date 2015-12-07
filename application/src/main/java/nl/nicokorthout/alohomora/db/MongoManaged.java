package nl.nicokorthout.alohomora.db;

import com.mongodb.Mongo;

import io.dropwizard.lifecycle.Managed;

/**
 * Created by nicokorthout on 07/12/15.
 */
public class MongoManaged implements Managed {

    private Mongo mongo;

    public MongoManaged(Mongo mongo) {
        this.mongo = mongo;
    }

    @Override
    public void start() throws Exception {
    }

    @Override
    public void stop() throws Exception {
        mongo.close();
    }

}
