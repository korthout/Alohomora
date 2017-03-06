package nl.nicokorthout.alohomora.core;

public enum Role {

    ADMIN("admin"),
    CUSTOMER("customer"),
    PROVIDER("provider");

    private final String name;

    Role(final String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

}
