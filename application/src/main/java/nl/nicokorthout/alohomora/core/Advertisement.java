package nl.nicokorthout.alohomora.core;

import com.google.common.base.Preconditions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;

import java.time.LocalDate;

import javax.validation.constraints.Min;

@JsonDeserialize(builder = Advertisement.AdvertisementBuilder.class)
public class Advertisement {

    private final int id;
    private final String name;
    private final String description;
    private final String city;
    private final String address;
    private final String zipcode;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    private final LocalDate creationDate;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    private final LocalDate lastModified;

    public static AdvertisementBuilder builder() {
        return new AdvertisementBuilder();
    }

    public Advertisement(AdvertisementBuilder builder) {
        Preconditions.checkNotNull(builder.name, "name is not set");
        Preconditions.checkNotNull(builder.description, "description is not set");
        Preconditions.checkNotNull(builder.city, "city is not set");
        Preconditions.checkNotNull(builder.address, "address is not set");
        Preconditions.checkNotNull(builder.zipcode, "zipcode is not set");
        Preconditions.checkNotNull(builder.creationDate, "creation date is not set");
        Preconditions.checkNotNull(builder.lastModified, "last modified is not set");

        this.id = builder.id;
        this.name = builder.name;
        this.description = builder.description;
        this.city = builder.city;
        this.address = builder.address;
        this.zipcode = builder.zipcode;
        this.creationDate = builder.creationDate;
        this.lastModified = builder.lastModified;
    }

    public int getId() {
        return id;
    }

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Advertisement that = (Advertisement) o;

        if (id != that.id) return false;
        if (name != null ? !name.equals(that.name) : that.name != null) return false;
        if (description != null ? !description.equals(that.description) : that.description != null)
            return false;
        if (city != null ? !city.equals(that.city) : that.city != null) return false;
        if (address != null ? !address.equals(that.address) : that.address != null) return false;
        if (zipcode != null ? !zipcode.equals(that.zipcode) : that.zipcode != null) return false;
        if (creationDate != null ? !creationDate.equals(that.creationDate) : that.creationDate != null)
            return false;
        return lastModified != null ? lastModified.equals(that.lastModified) : that.lastModified == null;
    }

    @Override
    public int hashCode() {
        int result = id;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        result = 31 * result + (description != null ? description.hashCode() : 0);
        result = 31 * result + (city != null ? city.hashCode() : 0);
        result = 31 * result + (address != null ? address.hashCode() : 0);
        result = 31 * result + (zipcode != null ? zipcode.hashCode() : 0);
        result = 31 * result + (creationDate != null ? creationDate.hashCode() : 0);
        result = 31 * result + (lastModified != null ? lastModified.hashCode() : 0);
        return result;
    }

    @JsonPOJOBuilder(buildMethodName = "build", withPrefix = "")
    public static class AdvertisementBuilder {

        @Min(1)
        private int id;

        private String name;
        private String description;
        private String city;
        private String address;
        private String zipcode;

        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate creationDate;

        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate lastModified;

        public AdvertisementBuilder() {
            this.id = 0;
            this.name = null;
            this.description = null;
            this.city = null;
            this.address = null;
            this.zipcode = null;
            this.creationDate = null;
            this.lastModified = null;
        }

        public AdvertisementBuilder id(int id) {
            this.id = id;
            return this;
        }

        public AdvertisementBuilder name(String name) {
            this.name = name;
            return this;
        }

        public AdvertisementBuilder description(String description) {
            this.description = description;
            return this;
        }

        public AdvertisementBuilder city(String city) {
            this.city = city;
            return this;
        }

        public AdvertisementBuilder address(String address) {
            this.address = address;
            return this;
        }

        public AdvertisementBuilder zipcode(String zipcode) {
            this.zipcode = zipcode;
            return this;
        }

        public AdvertisementBuilder creationDate(LocalDate creationDate) {
            this.creationDate = creationDate;
            return this;
        }

        public AdvertisementBuilder lastModified(LocalDate lastModified) {
            this.lastModified = lastModified;
            return this;
        }

        public Advertisement build() {
            return new Advertisement(this);
        }

    }

}
