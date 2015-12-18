package nl.nicokorthout.alohomora.db;

import org.skife.jdbi.v2.sqlobject.SqlUpdate;

/**
 * This interface is used to access the database's User table
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 18-12-2015
 */
public interface UserDAO {

    @SqlUpdate("create table if not exists User (Name varchar(20) primary key)")
    void createUserTable();

}
