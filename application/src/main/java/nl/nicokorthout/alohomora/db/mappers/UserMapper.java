package nl.nicokorthout.alohomora.db.mappers;

import nl.nicokorthout.alohomora.core.User;

import org.skife.jdbi.v2.StatementContext;
import org.skife.jdbi.v2.tweak.ResultSetMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Maps ResultSets from queries to Users.
 *
 * @author Nico Korthout
 * @version 0.1.1
 * @since 18-12-2015
 */
public class UserMapper implements ResultSetMapper<User> {

    @Override
    public User map(int index, ResultSet resultSet, StatementContext statementContext)
            throws SQLException {

        if (!resultSet.isBeforeFirst() ) {
            return null;
        }

        return User.builder()
                .username(resultSet.getString("username"))
                .registered(resultSet.getDate("registered").toLocalDate())
                .email(resultSet.getString("email"))
                .salt(resultSet.getBytes("salt"))
                .password(resultSet.getBytes("password"))
                .role(resultSet.getString("role"))
                .build();
    }

}