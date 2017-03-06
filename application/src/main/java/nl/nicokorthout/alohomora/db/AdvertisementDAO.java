package nl.nicokorthout.alohomora.db;

import nl.nicokorthout.alohomora.core.Advertisement;

/**
 * This interface is used to access the database's Advertisement table.
 */
public interface AdvertisementDAO {

    void store(Advertisement advertisement);
}
