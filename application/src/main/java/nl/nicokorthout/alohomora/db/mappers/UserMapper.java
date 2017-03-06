package nl.nicokorthout.alohomora.db.mappers;

import nl.nicokorthout.alohomora.core.User;

import org.skife.jdbi.v2.StatementContext;
import org.skife.jdbi.v2.tweak.ResultSetMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Maps ResultSets to Users.
 */
public class UserMapper implements ResultSetMapper<User> {

    @Override
    public User map(int index, ResultSet resultSet, StatementContext statementContext) throws SQLException {
        if (!resultSet.isBeforeFirst())
            return null;

        return buildUser(resultSet);
    }

    private User buildUser(ResultSet resultSet) throws SQLException {
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