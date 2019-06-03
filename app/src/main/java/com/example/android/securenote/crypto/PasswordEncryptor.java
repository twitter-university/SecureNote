package com.example.android.securenote.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

public class PasswordEncryptor {

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = KEY_LENGTH / 8;

    //Delimiter should be used between components of the ciphertext
    // We chose '&' because is not part of the Base64 character set
    private static final String DELIMITER = "&";

    private SecureRandom secureRandom;

    public PasswordEncryptor() {
        // Do *not* seed secureRandom! Automatically seeded from system entropy.
        secureRandom = new SecureRandom();
    }

    /**
     * Create a new symmetric key used in both encryption and decryption
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private SecretKey generateSecretKey(char[] passphraseOrPin, byte[] salt) throws
            NoSuchAlgorithmException, InvalidKeySpecException {
        /*
         * TODO: Encryption Lab:
         * Generate a new key from the supplied password+salt using AES.
         * Use KEY_LENGTH for the length of the generated key.
         */
        return null;
    }

    /**
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void encryptData(String passphrase, byte[] data, OutputStream out) throws
            GeneralSecurityException, IOException {
        /*
         * TODO: Encryption Lab:
         * Use SecureRandom to generate a new salt, length=SALT_LENGTH
         * Use SecureRandom to generate a new iv, length=getBlockSize()
         * Create and use a cipher to encrypt the incoming data (ENCRYPTION_ALGORITHM is already set).
         * Pack and write all three (salt,iv,encrypted) as a ciphertext blob to the provided stream.
         * - Each item should have a DELIMITER between it
         * Don't forget to Base64 encode everything you write to the file
         */
    }

    /**
     * Return decrypted data from the received cipher text blob.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public byte[] decryptData(String passphrase, InputStream in) throws
            GeneralSecurityException, IOException {
        /*
         * TODO: Encryption Lab:
         * Parse the ciphertext blob and unpack the stored iv, salt, and encrypted contents.
         * Construct and use a Cipher to decrypt the data.
         * Return the decrypted bytes.
         */
        return null;
    }

    /* Helper method to parse a file stream into memory */
    private String readFile(InputStream in) throws IOException {
        InputStreamReader reader = new InputStreamReader(in);
        StringBuilder sb = new StringBuilder();

        char[] inputBuffer = new char[2048];
        int read;
        while ((read = reader.read(inputBuffer)) != -1) {
            sb.append(inputBuffer, 0, read);
        }

        return sb.toString();
    }
}
