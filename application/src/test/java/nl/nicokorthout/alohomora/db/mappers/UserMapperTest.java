package nl.nicokorthout.alohomora.db.mappers;

import nl.nicokorthout.alohomora.core.User;

import org.junit.Test;
import org.skife.jdbi.v2.StatementContext;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by nicokorthout on 26/12/2016.
 */
public class UserMapperTest {

    @Test
    public void mapUser() throws SQLException {
        UserMapper mapper = new UserMapper();
        ResultSet resultSet = mock(ResultSet.class);
        StatementContext statementContext = mock(StatementContext.class);

        when(resultSet.isBeforeFirst()).thenReturn(true);
        when(resultSet.getString("username")).thenReturn("someName");
        when(resultSet.getDate("registered")).thenReturn(new Date(Date.from(Instant.now()).getTime()));
        when(resultSet.getString("email")).thenReturn("someEmail");
        when(resultSet.getString("role")).thenReturn("provider");

        User user = mapper.map(0, resultSet, statementContext);
        assertThat(user).isNotNull();
    }

    @Test
    public void mapNonExistingUser() throws SQLException {
        UserMapper mapper = new UserMapper();
        ResultSet resultSet = mock(ResultSet.class);
        StatementContext statementContext = mock(StatementContext.class);

        when(resultSet.isBeforeFirst()).thenReturn(false);
        User user = mapper.map(0, resultSet, statementContext);
        assertThat(user).isNull();
    }

}
