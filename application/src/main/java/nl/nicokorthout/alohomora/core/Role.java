package nl.nicokorthout.alohomora.core;

/**
 * Specification of different roles for user principals.
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 24-12-2015
 */
public enum Role {

    ADMIN("admin"),
    CUSTOMER("customer"),
    PROVIDER("provider");

    private final String name;

    /**
     * Constructor for Role.
     *
     * @param name The name of this Role.
     */
    Role(final String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

}
