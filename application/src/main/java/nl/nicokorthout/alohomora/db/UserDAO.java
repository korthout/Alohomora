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
 */
@RegisterMapper(UserMapper.class)
@RegisterArgumentFactory(LocalDateArgumentMapper.class)
public interface UserDAO {

    @SqlUpdate("create table if not exists user (" +
            "username varchar(20) not null primary key, " +
            "registered date not null, " +
            "email varchar(254) not null, " +
            "salt binary(8) not null, " +
            "password binary(64) not null, " +
            "role varchar(20) not null, " +
            "unique (email))")
    void createUserTableIfNotExists();

    @SqlUpdate("insert into user (username, registered, email, salt, password, role) " +
            "values (:username, :registered, :email, :salt, :password, :role)")
    void store(@BindBean User user);

    @SingleValueResult
    @SqlQuery("select username, registered, email, salt, password, role " +
            "from user " +
            "where username = :username")
    Optional<User> find(@Bind("username") String username);

    @SingleValueResult
    @SqlQuery("select username, registered, email, salt, password, role from user " +
            "where email = :email")
    Optional<User> findByEmail(@Bind("email") String email);

    @SqlUpdate("update user set email = :email, salt = :salt, password = :password " +
            "where username = :username")
    void update(@BindBean User user);
}
