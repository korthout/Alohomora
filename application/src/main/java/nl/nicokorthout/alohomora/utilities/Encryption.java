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
 *
 * @author Nico Korthout
 * @version 0.1.0
 * @since 18-12-2015
 */
public class Encryption {

    // 10000 or higher recommended
    private static final int HASHING_ITERATIONS = 10000;

    // 512 bit (64 byte) recommended
    private static final int KEY_LENGTH = 512;

    // 8 byte (64 bit) as recommended by RSA PKCS5
    private static final int SALT_LENGTH = 8;

    private SecretKeyFactory secretKeyFactory;
    private SecureRandom secureRandom;

    /**
     * Constructor for Encryption
     */
    public Encryption() {
        try {
            // Password Based Key Derivative Function 512 bits (64 bytes)
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Generate a new salt.
     *
     * @return newly generated salt.
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes a password using the given salt. Hashing is done using the initiated {@link
     * javax.crypto.SecretKeyFactory}.
     *
     * @param password the password to be hashed.
     * @param salt     bytes to add to the password when hashing.
     * @return hashed password in bytes.
     */
    public byte[] hashPassword(@NotNull String password, @NotNull byte[] salt) {
        Preconditions.checkNotNull(password, "password required");
        Preconditions.checkNotNull(salt, "salt required");
        char[] passwordChars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, HASHING_ITERATIONS, KEY_LENGTH);
        try {
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

//    /**
//     * The byte[] returned by MessageDigest does not have a nice textual representation, so some
//     * form of encoding is usually performed. <p> This implementation follows the example of David
//     * Flanagan's book "Java In A Nutshell", and converts a byte array into a String of hex
//     * characters. It has been slightly modified to comply modern standards. </p>
//     *
//     * @param input bytes to encode.
//     * @return String containing encoded bytes.
//     */
//    public String hexEncode(@NotNull byte[] input) {
//        Preconditions.checkNotNull(input, "input required");
//        StringBuilder result = new StringBuilder();
//        char[] digits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
//        for (byte b : input) {
//            result.append(digits[(b & 0xf0) >> 4]);
//            result.append(digits[b & 0x0f]);
//        }
//        return result.toString();
//    }

}
