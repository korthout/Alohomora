package nl.nicokorthout.alohomora.api;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

/**
 * Created by nicokorthout on 27/12/15.
 */
public class NewAdvertisement {

    @NotNull
    @Size(max = 50)
    private String name;

    @NotNull
    @Size(max = 500)
    private String description;

    @NotNull
    @Size(max = 20)
    private String city;

    @NotNull
    @Size(max = 50)
    private String address;

    @NotNull
    @Size(max = 20)
    private String zipcode;

    @JsonCreator
    public NewAdvertisement(@JsonProperty("name") String name,
                            @JsonProperty("description") String description,
                            @JsonProperty("city") String city,
                            @JsonProperty("address") String address,
                            @JsonProperty("zipcode") String zipcode) {
        this.name = name;
        this.description = description;
        this.city = city;
        this.address = address;
        this.zipcode = zipcode;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getCity() {
        return city;
    }

    public String getAddress() {
        return address;
    }

    public String getZipcode() {
        return zipcode;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NewAdvertisement that = (NewAdvertisement) o;

        if (name != null ? !name.equals(that.name) : that.name != null) return false;
        if (description != null ? !description.equals(that.description) : that.description != null)
            return false;
        if (city != null ? !city.equals(that.city) : that.city != null) return false;
        if (address != null ? !address.equals(that.address) : that.address != null) return false;
        return zipcode != null ? zipcode.equals(that.zipcode) : that.zipcode == null;
    }

    @Override
    public int hashCode() {
        int result = name != null ? name.hashCode() : 0;
        result = 31 * result + (description != null ? description.hashCode() : 0);
        result = 31 * result + (city != null ? city.hashCode() : 0);
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (zipcode != null ? zipcode.hashCode() : 0);
        return result;
    }

}
