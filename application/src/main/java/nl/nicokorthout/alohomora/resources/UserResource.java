package nl.nicokorthout.alohomora.resources;

import com.codahale.metrics.annotation.Timed;
import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;

import javax.validation.constraints.NotNull;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

/**
 * Created by nicokorthout on 06/12/15.
 */
@Path("/users")
public class UserResource {

    private final DB db;

    public UserResource(@NotNull DB db) {
        this.db = db;
    }

    @Timed
    @GET
    public String hello() {

        DBCollection table = db.getCollection("user");

        DBCursor cursor = table.find();
        DBObject object = null;
        if (cursor.hasNext()) {
            object = cursor.next();
        }

        int value = 0;
        if (object != null) {
            value = (int) object.get("value");
            table.remove(object);
        }
        value++;

        BasicDBObject document = new BasicDBObject();
        document.put("value", value);
        table.insert(document);

        return "Hello " + value;
    }

}
