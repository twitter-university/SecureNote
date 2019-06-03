package com.example.android.securenote.crypto;

import android.util.Base64;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordEncryptor {

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = KEY_LENGTH / 8;
    private static final String DELIMITER = "&";

    private SecureRandom secureRandom;

    public PasswordEncryptor() {
        // Do *not* seed secureRandom! Automatically seeded from system entropy.
        secureRandom = new SecureRandom();
    }

    /**
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void encryptData(String passphrase, byte[] data, OutputStream out) throws
            GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);

        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);

        Key key = generateSecretKey(passphrase.toCharArray(), salt);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        //Pack the result in a cipher text blob
        final byte[] encrypted = cipher.doFinal(data);
        try {
            out.write(Base64.encode(salt, Base64.NO_WRAP));
            out.write(DELIMITER.getBytes());
            out.write(Base64.encode(iv, Base64.NO_WRAP));
            out.write(DELIMITER.getBytes());
            out.write(Base64.encode(encrypted, Base64.NO_WRAP));

            out.flush();
        } finally {
            out.close();
        }
    }

    /**
     * Return decrypted data from the received cipher text blob.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public byte[] decryptData(String passphrase, InputStream in) throws
            GeneralSecurityException, IOException {
        //Unpack cipherText
        String cipherText = readFile(in);
        String[] fields = cipherText.split(DELIMITER);
        if (fields.length != 3) {
            throw new IllegalArgumentException("Not a valid cipher text blob");
        }

        final byte[] salt = Base64.decode(fields[0], Base64.NO_WRAP);
        final byte[] iv = Base64.decode(fields[1], Base64.NO_WRAP);
        final byte[] encrypted = Base64.decode(fields[2], Base64.NO_WRAP);

        Key key = generateSecretKey(passphrase.toCharArray(), salt);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(encrypted);
    }

    private SecretKey generateSecretKey(char[] passphraseOrPin, byte[] salt) throws
            NoSuchAlgorithmException, InvalidKeySpecException {
        // Number of PBKDF2 hardening rounds to use. Larger values increase
        // computation time. You should select a value that causes computation
        // to take >100ms.
        final int iterations = 1000;

        SecretKeyFactory secretKeyFactory =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec =
                new PBEKeySpec(passphraseOrPin, salt, iterations, KEY_LENGTH);
        byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

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
