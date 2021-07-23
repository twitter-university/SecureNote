package com.example.android.securenote.crypto

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Base64InputStream
import android.util.Base64OutputStream
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAKeyGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream


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
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Throws(GeneralSecurityException::class, IOException::class)
    fun encryptData(data: ByteArray, outputStream: OutputStream) {
        val key = retrievePublicKey()
        val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        // Encode output to file
        var out: OutputStream = Base64OutputStream(outputStream, Base64.NO_WRAP)

        // Encrypt output to encoder
        out = CipherOutputStream(out, cipher)

        try {
            out.write(data)
            out.flush()
        } finally {
            out.close()
        }
    }

    /**
     * Return decrypted data from the received cipher text blob.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Throws(GeneralSecurityException::class, IOException::class)
    fun decryptData(inputStream: InputStream): ByteArray {
        val privateKey = retrievePrivateKey()

        val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        //Decode input from file
        var input: InputStream = Base64InputStream(inputStream, Base64.NO_WRAP)
        //Decrypt input from decoder
        input = CipherInputStream(input, cipher)

        return readFile(input).toByteArray(Charsets.UTF_8)
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    fun retrievePublicKey(): Key {
        val encodedKey = sharedPreferences.getString(KEY_PUBLIC, null)
            ?: throw RuntimeException("Expected valid public key!")

        val publicKey = Base64.decode(encodedKey, Base64.NO_WRAP)
        return KeyFactory.getInstance(KEY_ALGORITHM)
            .generatePublic(X509EncodedKeySpec(publicKey))
    }

    private fun retrievePrivateKey(): PrivateKey? {
        val keyStore = KeyStore.getInstance(PROVIDER_NAME).apply {
            load(null)
        }

        val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry

        return entry.privateKey
    }

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
        private val TAG = "RSAHardwareEncryptor"
        private const val PROVIDER_NAME = "AndroidKeyStore"
        private const val KEY_ALGORITHM = "RSA"
        private const val ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding"

        private const val KEY_PUBLIC = "publickey"

        //KeyStore alias for the private key
        private const val KEY_ALIAS = "secureKeyAlias"
    }
}
