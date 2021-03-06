package nl.nicokorthout.alohomora.api;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import nl.nicokorthout.alohomora.core.Role;

import org.apache.commons.validator.routines.EmailValidator;

import java.util.Arrays;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import io.dropwizard.validation.ValidationMethod;

public class NewUser {

    @NotNull
    @Size(min = 1, max = 20)
    private final String username;

    @NotNull
    @Size(min = 3)
    private final String password;

    @NotNull
    @Size(min = 1, max = 254)
    private final String email;

    @NotNull
    private final String role;

    @JsonCreator
    public NewUser(@JsonProperty(value = "username") String username,
                   @JsonProperty(value = "password") String password,
                   @JsonProperty(value = "email") String email,
                   @JsonProperty(value = "role") String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
    }

    @ValidationMethod(message = "username may not be admin")
    @JsonIgnore
    public boolean isNotAdmin() {
        return !"admin".equalsIgnoreCase(username);
    }

    @ValidationMethod(message = "username may not be me")
    @JsonIgnore
    public boolean isNotMe() {
        return !"me".equalsIgnoreCase(username);
    }

    @ValidationMethod(message = "username must be alphanumeric")
    @JsonIgnore
    public boolean isUsernameAlphanumeric() {
        return username != null && username.chars().allMatch(Character::isLetterOrDigit);
    }

    @ValidationMethod(message = "email must be valid")
    @JsonIgnore
    public boolean isEmailValid() {
        return EmailValidator.getInstance().isValid(email);
    }

    @ValidationMethod(message = "role must be an existing role")
    @JsonIgnore
    public boolean isRoleCorrect() {
        return role != null && Arrays.asList(Role.values())
                .stream()
                .map(Role::toString)
                .anyMatch(x -> x.equals(role));
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

    public String getRole() {
        return role;
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
        if (email != null ? !email.equals(newUser.email) : newUser.email != null) return false;
        return role != null ? role.equals(newUser.role) : newUser.role == null;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (password != null ? password.hashCode() : 0);
        result = 31 * result + (email != null ? email.hashCode() : 0);
        result = 31 * result + (role != null ? role.hashCode() : 0);
        return result;
    }
}

