package nl.nicokorthout.alohomora.core;

import com.google.common.base.Preconditions;

import nl.nicokorthout.alohomora.api.NewUser;
import nl.nicokorthout.alohomora.db.UserDAO;
import nl.nicokorthout.alohomora.utilities.Encryption;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class UserRegistration {

    private final Logger logger = LoggerFactory.getLogger(UserRegistration.class);
    private final UserDAO userDAO;
    private final Encryption encryption;

    public UserRegistration(@NotNull UserDAO userDAO, @NotNull Encryption encryption) {
        this.userDAO = Preconditions.checkNotNull(userDAO, "UserDAO is not set");
        this.encryption = Preconditions.checkNotNull(encryption, "Encryption is not set");;
    }

    public User registerUser(@NotNull NewUser newUser) {
        User user = createUserFromNewUser(newUser);
        userDAO.store(user);
        logger.debug("Registered user '{}'", user.getUsername());
        return user;
    }

    private User createUserFromNewUser(@NotNull @Valid NewUser newUser) {
        final byte[] salt = encryption.generateSalt();
        final byte[] hashedPassword = encryption.hashPassword(newUser.getPassword(), salt);
        return User.builder()
                .username(newUser.getUsername())
                .registered(LocalDate.now())
                .email(newUser.getEmail())
                .salt(salt)
                .password(hashedPassword)
                .role(newUser.getRole())
                .build();
    }

    public boolean checkUsernameAvailable(@NotNull NewUser newUser) {
        if (userDAO.find(newUser.getUsername()).isPresent()) {
            logger.debug("Duplicate username: '{}'", newUser.getUsername());
            return false;
        }
        return true;
    }

    public boolean checkEmailAvailable(@NotNull NewUser newUser) {
        if (userDAO.findByEmail(newUser.getEmail()).isPresent()) {
            logger.debug("Duplicate email: '{}'", newUser.getEmail());
            return false;
        }
        return true;
    }
}