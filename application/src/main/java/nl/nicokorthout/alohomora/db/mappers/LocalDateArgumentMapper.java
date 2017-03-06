package nl.nicokorthout.alohomora.db.mappers;

import org.skife.jdbi.v2.StatementContext;
import org.skife.jdbi.v2.tweak.Argument;
import org.skife.jdbi.v2.tweak.ArgumentFactory;

import java.sql.Date;
import java.time.LocalDate;

/**
 * Maps java.time.LocalDate arguments to java.sql.Date.
 */
public class LocalDateArgumentMapper implements ArgumentFactory<LocalDate> {

    @Override
    public boolean accepts(Class<?> expectedType, Object value, StatementContext statementContext) {
        return value != null && LocalDate.class.isAssignableFrom(value.getClass());
    }

    @Override
    public Argument build(Class<?> expectedType, final LocalDate localDate,
                          StatementContext statementContext) {
        return (position, statement, statementContext1) ->
                statement.setDate(position, Date.valueOf(localDate));
    }

}
