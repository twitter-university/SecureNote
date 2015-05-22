package com.example.android.securenote.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyChain;
import android.security.KeyPairGeneratorSpec;
import android.util.Base64;
import android.util.Base64InputStream;
import android.util.Base64OutputStream;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

public class RSAHardwareEncryptor {
    private static final String TAG =
            RSAHardwareEncryptor.class.getSimpleName();
    private static final String PROVIDER_NAME = "AndroidKeyStore";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";

    //Preferences alias for the public key
    private static final String KEY_PUBLIC = "publickey";
    //KeyStore alias for the private key
    private static final String KEY_ALIAS = "secureKeyAlias";

    //Persistent location where we will save the public key
    private SharedPreferences mPublicKeyStore;

    public RSAHardwareEncryptor(Context context) {
        mPublicKeyStore = context.getSharedPreferences(
                "publickey.store", Context.MODE_PRIVATE);
        try {
            if (!mPublicKeyStore.contains(KEY_PUBLIC)) {
                generatePrivateKey(context);
                Log.d(TAG, "Generated hardware-bound key");
            } else {
                Log.d(TAG, "Hardware key pair already exists");
            }
        } catch (Exception e) {
            throw new RuntimeException("Unable to generate key material.");
        }
    }

    /**
     * Create a self-signed certificate and private key in hardware storage.
     * Persist the (non-secret) public key into SharedPreferences.
     *
     * @throws GeneralSecurityException
     */
    private void generatePrivateKey(Context context) throws
            GeneralSecurityException {
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cal.add(Calendar.YEAR, 1);
        Date end = cal.getTime();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM, PROVIDER_NAME);
        kpg.initialize(new KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEY_ALIAS)
                .setStartDate(now)
                .setEndDate(end)
                .setSerialNumber(BigInteger.valueOf(1))
                .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                .build());

        //Generate and bind the private key to hardware
        KeyPair kp = kpg.generateKeyPair();

        //Persist the public key
        PublicKey publicKey = kp.getPublic();
        String encodedKey = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
        mPublicKeyStore.edit().putString(KEY_PUBLIC, encodedKey).apply();
    }

    /**
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void encryptData(byte[] data, OutputStream out) throws
            GeneralSecurityException, IOException {
        /*
         * TODO: Encryption Lab:
         * Obtain the public key for encryption
         * Create and init a Cipher (with ENCRYPTION_ALGORITHM)
         * Wrap the supplied stream in another provides Base64 encoding
         * Wrap the encoding stream in another that encrypts with cipher
         * Write the supplied data to the streams.
         */
    }

    /**
     * Return decrypted data from the received cipher text blob.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public byte[] decryptData(InputStream in) throws
            GeneralSecurityException, IOException {
        /*
         * TODO: Encryption Lab:
         * Obtain the private key for decryption
         * Create and init a Cipher (with ENCRYPTION_ALGORITHM)
         * Wrap the supplied stream in another parses Base64 encoding
         * Wrap the encoding stream in another that decrypts with cipher
         * Read the stream fully and return the decrypted bytes
         */
        return null;
    }

    public Key retrievePublicKey() throws
            NoSuchAlgorithmException, InvalidKeySpecException {
        /*
         * TODO: Encryption Lab:
         * Get the encoded key from SharedPreferences
         * Decode the key (from Base64) to raw bytes
         * Return a public key instance from the bytes using KeyFactory
         */
        return null;
    }

    public Key retrievePrivateKey() throws
            GeneralSecurityException, IOException {
        /*
         * TODO: Encryption Lab:
         * Obtain an instance of AndroidKeyStore and load it
         * Get the private key alias and return the key
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
