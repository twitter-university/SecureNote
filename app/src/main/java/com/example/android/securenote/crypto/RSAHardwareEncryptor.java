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

    private static final String KEY_PUBLIC = "publickey";
    private static final String KEY_ALIAS = "secureKeyAlias";

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
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void encryptData(byte[] data, OutputStream out) throws
            GeneralSecurityException, IOException {
        Key key = retrievePublicKey();
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        //Encode output to file
        out = new Base64OutputStream(out, Base64.NO_WRAP);
        //Encrypt output to encoder
        out = new CipherOutputStream(out, cipher);

        try {
            out.write(data);
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
    public byte[] decryptData(InputStream in) throws
            GeneralSecurityException, IOException {
        Key key = retrievePrivateKey();
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);

        //Decode input from file
        in = new Base64InputStream(in, Base64.NO_WRAP);
        //Decrypt input from decoder
        in = new CipherInputStream(in, cipher);

        return readFile(in).getBytes();
    }

    public Key retrievePublicKey() throws
            NoSuchAlgorithmException, InvalidKeySpecException {
        String encodedKey = mPublicKeyStore.getString(KEY_PUBLIC, null);
        if (encodedKey == null) {
            throw new RuntimeException("Expected valid public key!");
        }

        byte[] publicKey = Base64.decode(encodedKey, Base64.NO_WRAP);
        return KeyFactory.getInstance(KEY_ALGORITHM)
                        .generatePublic(new X509EncodedKeySpec(publicKey));
    }

    public Key retrievePrivateKey() throws
            GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(PROVIDER_NAME);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return null;
        }

        return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    }

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
