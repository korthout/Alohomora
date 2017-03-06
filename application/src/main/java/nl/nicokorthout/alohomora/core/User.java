package nl.nicokorthout.alohomora.core;

import com.google.common.base.Preconditions;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;


import java.security.Principal;
import java.time.LocalDate;
import java.util.Arrays;

import javax.validation.constraints.NotNull;

@JsonDeserialize(builder = User.UserBuilder.class)
public class User implements Principal {

    private final String username;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    private final LocalDate registered;

    private final String email;

    @JsonIgnore
    private final byte[] salt;

    @JsonIgnore
    private final byte[] password;

    private final String role;

    public static UserBuilder builder() {
        return new UserBuilder();
    }

    public User(UserBuilder builder) {
        this.username = Preconditions.checkNotNull(builder.username, "username is not set");
        this.registered = Preconditions.checkNotNull(builder.registered, "registered is not set");
        this.email = Preconditions.checkNotNull(builder.email, "email is not set");
        this.salt = builder.salt;
        this.password = builder.password;
        this.role = Preconditions.checkNotNull(builder.role, "role is not set");
    }

    /**
     * Retrieve a new UserBuilder object representing this User object.
     * This can be used to make alterations to this object.
     * Remember that this User object is immutable and cannot be altered.
     * The new builder is only able to build a new User object.
     *
     * @return A UserBuilder object with the same values as this object.
     */
    public UserBuilder asBuilder() {
        return new UserBuilder()
                .username(username)
                .registered(registered)
                .email(email)
                .salt(salt)
                .password(password)
                .role(role);
    }

    public String getUsername() {
        return username;
    }

    public LocalDate getRegistered() {
        return registered;
    }

    public String getEmail() {
        return email;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getPassword() {
        return password;
    }

    public String getRole() {
        return role;
    }

    @JsonIgnore
    @Override
    public String getName() {
        return username;
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

        User user = (User) o;

        if (username != null ? !username.equals(user.username) : user.username != null)
            return false;
        if (registered != null ? !registered.equals(user.registered) : user.registered != null)
            return false;
        if (email != null ? !email.equals(user.email) : user.email != null) return false;
        if (!Arrays.equals(salt, user.salt)) return false;
        if (!Arrays.equals(password, user.password)) return false;
        return role != null ? role.equals(user.role) : user.role == null;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (registered != null ? registered.hashCode() : 0);
        result = 31 * result + (email != null ? email.hashCode() : 0);
        result = 31 * result + Arrays.hashCode(salt);
        result = 31 * result + Arrays.hashCode(password);
        result = 31 * result + (role != null ? role.hashCode() : 0);
        return result;
    }

    @JsonPOJOBuilder(buildMethodName = "build", withPrefix = "")
    public static class UserBuilder {

        @NotNull
        private String username;

        @NotNull
        @JsonDeserialize(using = LocalDateDeserializer.class)
        @JsonSerialize(using = LocalDateSerializer.class)
        private LocalDate registered;

        @NotNull
        private String email;

        private byte[] salt;
        private byte[] password;

        @NotNull
        private String role;

        public UserBuilder() {
            this.username = null;
            this.registered = null;
            this.email = null;
            this.salt = null;
            this.password = null;
            this.role = null;
        }

        public UserBuilder username(String username) {
            this.username = username;
            return this;
        }

        public UserBuilder registered(LocalDate registered) {
            this.registered = registered;
            return this;
        }

        public UserBuilder email(String email) {
            this.email = email;
            return this;
        }

        public UserBuilder salt(byte[] salt) {
            this.salt = salt;
            return this;
        }

        public UserBuilder password(byte[] password) {
            this.password = password;
            return this;
        }

        public UserBuilder role(String role) {
            this.role = role;
            return this;
        }

        public User build() {
            return new User(this);
        }

    }

}