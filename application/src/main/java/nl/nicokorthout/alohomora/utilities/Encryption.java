package nl.nicokorthout.alohomora.utilities;

import com.google.common.base.Preconditions;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.validation.constraints.NotNull;

/**
 * The Encryption class is a utility to encrypt Strings (e.g. passwords).
 */
public class Encryption {

    // 10000 or higher recommended
    private static final int HASHING_ITERATIONS = 10000;

    // 512 bit (64 byte) recommended
    private static final int KEY_LENGTH = 512;

    // 8 byte (64 bit) as recommended by RSA PKCS5
    private static final int SALT_LENGTH = 8;

    // Password Based Key Derivative Function 512 bits (64 bytes)
    private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA512";

    // SHA-1 is not secure, but is fine to use for generating some simply randomness like a salt.
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";

    private final SecretKeyFactory secretKeyFactory;
    private final SecureRandom randomGenerator;

    public Encryption() {
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
            randomGenerator = SecureRandom.getInstance(RANDOM_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        randomGenerator.nextBytes(salt);
        return salt;
    }

    public byte[] hashPassword(@NotNull String password, @NotNull byte[] salt) {
        Preconditions.checkNotNull(password, "password required");
        Preconditions.checkNotNull(salt, "salt required");
        char[] passwordChars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, HASHING_ITERATIONS, KEY_LENGTH);
        try {
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * The byte[] returned by MessageDigest does not have a nice textual representation, so some
     * form of encoding is usually performed.
     *
     * This implementation follows the example of David Flanagan's book "Java In A Nutshell",
     * and converts a byte array into a String of hex characters.
     * It has been slightly modified to comply modern standards.
     *
     * @param input bytes to encode.
     * @return String containing encoded bytes.
     */
    public String hexEncode(@NotNull byte[] input) {
        Preconditions.checkNotNull(input, "input required");
        StringBuilder result = new StringBuilder();
        char[] digits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        for (byte b : input) {
            result.append(digits[(b & 0xf0) >> 4]);
            result.append(digits[b & 0x0f]);
        }
        return result.toString();
    }

}
