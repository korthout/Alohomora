package nl.nicokorthout.alohomora;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.hibernate.validator.constraints.NotEmpty;

import java.io.UnsupportedEncodingException;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.dropwizard.Configuration;
import io.dropwizard.db.DataSourceFactory;

/**
 * This class allows configuration of the application. It reads the Alohomora.yml file as its
 * configuration.
 *
 * @author Nico Korthout
 * @version 0.3.0
 * @since 06-12-2015
 */
public class AlohomoraConfiguration extends Configuration {

    @Valid
    @NotNull
    private DataSourceFactory database = new DataSourceFactory();

    @NotEmpty
    private String jsonWebTokenSecret;

    @JsonProperty("database")
    public void setDataSourceFactory(DataSourceFactory database) {
        this.database = database;
    }

    @JsonProperty("database")
    public DataSourceFactory getDataSourceFactory() {
        return database;
    }

    @JsonProperty("jsonWebTokenSecret")
    public byte[] getJsonWebTokenSecret() {
        try {
            return jsonWebTokenSecret.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Could not retrieve JSON Web Token from config", e);
        }
    }

    @JsonProperty("jsonWebTokenSecret")
    public void setJsonWebTokenSecret(String jsonWebTokenSecret) {
        this.jsonWebTokenSecret = jsonWebTokenSecret;
    }
}
