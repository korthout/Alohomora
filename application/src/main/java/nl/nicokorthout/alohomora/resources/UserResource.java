package nl.nicokorthout.alohomora.resources;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

/**
 * Created by nicokorthout on 06/12/15.
 */
@Path("/users")
public class UserResource {

    @GET
    public String hello() {
        return "Hello";
    }

}
