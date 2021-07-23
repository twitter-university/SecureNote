package com.example.android.securenote.crypto

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.math.BigInteger
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAKeyGenParameterSpec
import java.util.*
import javax.security.auth.x500.X500Principal


class RSAHardwareEncryptor(context: Context) {
    var masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    //Persistent location where we will save the public key
    private val sharedPreferences: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "secret_shared_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    init {
        try {
            if (!sharedPreferences.contains(KEY_PUBLIC)) {
                generatePrivateKey()
                Log.d(TAG, "Generated hardware-bound key")
            } else {
                Log.d(TAG, "Hardware key pair already exists")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Unable to generate key material.", e)
            throw RuntimeException("Unable to generate key material.")
        }
    }

    /**
     * Create a self-signed certificate and private key in hardware storage.
     * Persist the (non-secret) public key into SharedPreferences.
     *
     * @throws GeneralSecurityException
     */
    @Throws(GeneralSecurityException::class)
    private fun generatePrivateKey() {
        val keyPairGenerator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PROVIDER_NAME)
        keyPairGenerator.initialize(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setDigests(
                    KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384,
                    KeyProperties.DIGEST_SHA512
                )
                //.setUserAuthenticationRequired(true) <-- requires fingerprint
                .build()
        )
        val keyPair = keyPairGenerator.generateKeyPair()

        // Persist the public key
        val publicKey = keyPair.public
        val encodedKey = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
        sharedPreferences.edit().putString(KEY_PUBLIC, encodedKey).apply()
    }

    /**
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Throws(GeneralSecurityException::class, IOException::class)
    fun encryptData(data: ByteArray, out: OutputStream) {
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
    @Throws(GeneralSecurityException::class, IOException::class)
    fun decryptData(input: InputStream): ByteArray? {
        /*
         * TODO: Encryption Lab:
         * Obtain the private key for decryption
         * Create and init a Cipher (with ENCRYPTION_ALGORITHM)
         * Wrap the supplied stream in another parses Base64 encoding
         * Wrap the encoding stream in another that decrypts with cipher
         * Read the stream fully and return the decrypted bytes
         */
        return null
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun retrievePublicKey(): Key? {
        /*
         * TODO: Encryption Lab:
         * Get the encoded key from SharedPreferences
         * Decode the key (from Base64) to raw bytes
         * Return a public key instance from the bytes using KeyFactory
         */
        return null
    }

    fun retrievePrivateKey(): PrivateKey? {
        /*
         * TODO: Encryption Lab:
         * Obtain an instance of AndroidKeyStore and load it
         * Get the private key alias and return the key
         */
        return null
    }

    /* Helper method to parse a file stream into memory */
    @Throws(IOException::class)
    private fun readFile(input: InputStream): String {
        val reader = InputStreamReader(input)
        val sb = StringBuilder()

        val inputBuffer = CharArray(2048)
        var read: Int = reader.read(inputBuffer)
        while (read != -1) {
            sb.append(inputBuffer, 0, read)
            read = reader.read(inputBuffer)
        }

        return sb.toString()
    }

    companion object {
        private val TAG = RSAHardwareEncryptor::class.java.simpleName
        private const val PROVIDER_NAME = "AndroidKeyStore"
        private const val KEY_ALGORITHM = "RSA"
        private const val ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding"

        //Preferences alias for the public key
        private const val KEY_PUBLIC = "publickey"

        //KeyStore alias for the private key
        private const val KEY_ALIAS = "secureKeyAlias"
    }
}
