package nl.nicokorthout.alohomora.api;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import io.dropwizard.validation.ValidationMethod;

/**
 * Representation of a new User for the system. Contains everything that is necessary for creating
 * a new User.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 19-12-2015
 */
public class NewUser {

    @NotNull
    @Size(min = 1, max = 20)
    private String username;

    @NotNull
    @Size(min = 3)
    private String password;

    @NotNull
    @Size(min = 1, max = 254)
    private String email;

    @JsonCreator
    public NewUser() {
    }

    public NewUser(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }

    @ValidationMethod(message="name may not be admin")
    @JsonIgnore
    public boolean isNotAdmin() {
        return !"admin".equalsIgnoreCase(username);
    }

    @ValidationMethod(message="name may not be me")
    @JsonIgnore
    public boolean isNotMe() {
        return !"me".equalsIgnoreCase(username);
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NewUser newUser = (NewUser) o;

        if (username != null ? !username.equals(newUser.username) : newUser.username != null)
            return false;
        if (password != null ? !password.equals(newUser.password) : newUser.password != null)
            return false;
        return email != null ? email.equals(newUser.email) : newUser.email == null;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (email != null ? email.hashCode() : 0);
        return result;
    }

}

