package nl.nicokorthout.alohomora.core;

import com.google.common.base.Preconditions;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.LocalDate;

/**
 * A User represents a person using the system.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 18-12-2015
 */
public class User {

    private final String username;
    private final LocalDate registered;
    private final String email;

    @JsonIgnore
    private final byte[] salt;

    @JsonIgnore
    private final byte[] password;

    public static UserBuilder builder() {
        return new UserBuilder();
    }

    public User(UserBuilder builder) {
        this.username = Preconditions.checkNotNull(builder.username, "username is not set");
        this.registered = Preconditions.checkNotNull(builder.registered, "registered is not set");
        this.email = Preconditions.checkNotNull(builder.email, "email is not set");
        this.salt = Preconditions.checkNotNull(builder.salt, "salt is not set");
        this.password = Preconditions.checkNotNull(builder.password, "password is not set");
    }

    /**
     * Retrieve a new UserBuilder object representing this User object. This can be used to make
     * alterations to this object. Remember that this User object is immutable and cannot be
     * altered. The new builder is only able to build a new User object.
     *
     * @return A UserBuilder object with the same values as this object.
     */
    public UserBuilder asBuilder() {
        return new UserBuilder()
                .username(username)
                .registered(registered)
                .email(email)
                .salt(salt)
                .password(password);
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

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public static class UserBuilder {

        private String username;
        private LocalDate registered;
        private String email;
        private byte[] salt;
        private byte[] password;

        public UserBuilder() {
            this.username = null;
            this.registered = null;
            this.email = null;
            this.salt = null;
            this.password = null;
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

        public User build() {
            return new User(this);
        }

    }

}