package nl.nicokorthout.alohomora.resources;

import com.google.common.base.Preconditions;

import nl.nicokorthout.alohomora.api.NewAdvertisement;
import nl.nicokorthout.alohomora.core.Advertisement;
import nl.nicokorthout.alohomora.db.AdvertisementDAO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.LocalDate;

import javax.annotation.security.RolesAllowed;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

/**
 * The advertisement resource provides access to advertisement functions as a REST-ful API.
 */
@Path("advertisements")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AdvertisementResource {

    private final Logger logger = LoggerFactory.getLogger(AdvertisementResource.class);

    private final AdvertisementDAO dao;

    public AdvertisementResource(@NotNull AdvertisementDAO dao) {
        this.dao = Preconditions.checkNotNull(dao, "AdvertisementDAO is not set");
    }

    @POST
    @RolesAllowed("provider")
    public Response createAdvertisement(@NotNull @Valid NewAdvertisement newAdvertisement, @Context UriInfo uriInfo) {
        LocalDate now = LocalDate.now();
        Advertisement advertisement = Advertisement.builder()
                .name(newAdvertisement.getName())
                .description(newAdvertisement.getDescription())
                .city(newAdvertisement.getCity())
                .address(newAdvertisement.getAddress())
                .zipcode(newAdvertisement.getZipcode())
                .creationDate(now)
                .lastModified(now)
                .build();

        dao.store(advertisement);
        logger.info("Created advertisement '{}'", advertisement.getId());

        // Respond: 201 Created with location header pointing to advertisement URI
        URI location = uriInfo.getBaseUriBuilder().path("users/me/token").build();
        return Response.created(location)
                .entity("{\"advertisement\":\"" + advertisement.getId() + "\"}")
                .build();
    }

}
