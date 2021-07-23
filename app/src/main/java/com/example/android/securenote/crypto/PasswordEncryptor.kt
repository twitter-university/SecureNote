package com.example.android.securenote.crypto

import android.util.Base64
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException

import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object PasswordEncryptor {
    private const val ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding"
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = KEY_LENGTH / 8
    private const val DELIMITER = "&"

    // Do *not* seed secureRandom! Automatically seeded from system entropy.
    private val secureRandom: SecureRandom = SecureRandom()

    /**
     * Return a cipher text blob of encrypted data, Base64 encoded.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Throws(GeneralSecurityException::class, IOException::class)
    fun encryptData(passphrase: String, data: ByteArray, out: OutputStream) {
        val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM)

        val salt = ByteArray(SALT_LENGTH)
        secureRandom.nextBytes(salt)

        val iv = ByteArray(cipher.blockSize)
        secureRandom.nextBytes(iv)

        val key = generateSecretKey(passphrase.toCharArray(), salt)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))

        //Pack the result in a cipher text blob
        val encrypted = cipher.doFinal(data)
        out.write(Base64.encode(salt, Base64.NO_WRAP))
        out.write(DELIMITER.toByteArray())
        out.write(Base64.encode(iv, Base64.NO_WRAP))
        out.write(DELIMITER.toByteArray())
        out.write(Base64.encode(encrypted, Base64.NO_WRAP))
        out.flush()
        out.close()
    }

    /**
     * Return decrypted data from the received cipher text blob.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @Throws(GeneralSecurityException::class, IOException::class)
    fun decryptData(passphrase: String, input: InputStream): ByteArray {
        //Unpack cipherText
        val cipherText = readFile(input)
        val fields =
            cipherText.split(DELIMITER.toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        if (fields.size != 3) {
            throw IllegalArgumentException("Not a valid cipher text blob")
        }

        val salt = Base64.decode(fields[0], Base64.NO_WRAP)
        val iv = Base64.decode(fields[1], Base64.NO_WRAP)
        val encrypted = Base64.decode(fields[2], Base64.NO_WRAP)

        val key = generateSecretKey(passphrase.toCharArray(), salt)
        val cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM)

        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))

        return cipher.doFinal(encrypted)
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun generateSecretKey(passphraseOrPin: CharArray, salt: ByteArray): SecretKey {
        // Number of PBKDF2 hardening rounds to use. Larger values increase
        // computation time. You should select a value that causes computation
        // to take >100ms.
        val iterations = 1000

        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val keySpec = PBEKeySpec(passphraseOrPin, salt, iterations, KEY_LENGTH)
        val keyBytes = secretKeyFactory.generateSecret(keySpec).encoded
        return SecretKeySpec(keyBytes, "AES")
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
}
