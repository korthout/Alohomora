package nl.nicokorthout.alohomora.db;

import com.codahale.metrics.health.HealthCheck;
import com.mongodb.Mongo;
import com.mongodb.MongoException;

/**
 * Created by nicokorthout on 07/12/15.
 */
public class MongoHealthCheck extends HealthCheck {

    private Mongo mongo;

    public MongoHealthCheck(Mongo mongo) {
        this.mongo = mongo;
    }

    @Override
    protected Result check() throws Exception {
        try {
            mongo.getDatabaseNames();
            return Result.healthy();
        } catch (MongoException e) {
            return Result.unhealthy("database unavailable");
        }
    }

}
