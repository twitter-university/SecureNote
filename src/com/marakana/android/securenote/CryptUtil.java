
package com.marakana.android.securenote;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptUtil {

    public static final int IV_LENGTH = 16;

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";

    private static final String KEY_ALGORITHM = "AES";

    private static final int KEY_SIZE = 256;

    public static Key getKey(byte[] secret) throws NoSuchAlgorithmException {
        return getKey(secret, false);
    }

    public static Key getKey(byte[] secret, boolean wipeSecret) throws NoSuchAlgorithmException {
        // generate an encryption/decryption key from random data seeded with
        // our secret (i.e. password)
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(secret);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(KEY_SIZE, secureRandom);
        Key key = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), KEY_ALGORITHM);
        if (wipeSecret) {
            Arrays.fill(secret, (byte)0);
        }
        return key;
    }

    public static Cipher getEncryptCipher(Key key) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher;
    }

    public static Cipher getDecryptCipher(Key key, byte[] iv) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher;
    }

    public static byte[] getIv(Cipher cipher) throws InvalidParameterSpecException {
        return cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
    }

    public static byte[] getIv(InputStream in) throws IOException {
        byte[] iv = new byte[IV_LENGTH];
        for (int i = 0; i < iv.length;) {
            int nRead = in.read(iv, i, iv.length - i);
            if (nRead == -1) {
                throw new EOFException("Unexpected EOF");
            } else {
                i += nRead;
            }
        }
        return iv;
    }
}
