package nl.nicokorthout.alohomora.db;

import nl.nicokorthout.alohomora.core.User;
import nl.nicokorthout.alohomora.db.mappers.UserMapper;
import nl.nicokorthout.alohomora.db.mappers.LocalDateArgumentMapper;

import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.BindBean;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterArgumentFactory;
import org.skife.jdbi.v2.sqlobject.customizers.RegisterMapper;
import org.skife.jdbi.v2.sqlobject.customizers.SingleValueResult;

import java.util.Optional;

/**
 * This interface is used to access the database's User table.
 *
 * @author Nico Korthout
 * @version 0.3.0
 * @since 18-12-2015
 */
@RegisterMapper(UserMapper.class)
@RegisterArgumentFactory(LocalDateArgumentMapper.class)
public interface UserDAO {

    /**
     * Creates a new User table, if it does not yet exists.
     */
    @SqlUpdate("create table if not exists user (" +
            "username varchar(20) not null primary key, " +
            "registered date not null, " +
            "email varchar(254) not null, " +
            "salt binary(8) not null, " +
            "password binary(64) not null, " +
            "unique (email))")
    void createUserTable();

    /**
     * Store a User in the database.
     *
     * @param user The user to store.
     */
    @SqlUpdate("insert into user (username, registered, email, salt, password) " +
            "values (:username, :registered, :email, :salt, :password)")
    void store(@BindBean User user);

    /**
     * Find a User by its username.
     *
     * @param username The username to find the user by.
     * @return An Optional containing the found user, or an empty Optional if not.
     */
    @SingleValueResult
    @SqlQuery("select username, registered, email, salt, password from user " +
            "where username = :username")
    Optional<User> find(@Bind("username") String username);

    /**
     * Find a User by its email.
     *
     * @param email The email to find the user by
     * @return An Optional containing the found user, or an empty Optional if not.
     */
    @SingleValueResult
    @SqlQuery("select username, registered, email, salt, password from user " +
            "where email = :email")
    Optional<User> findByEmail(@Bind("email") String email);
}
