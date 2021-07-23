package com.example.android.securenote.crypto

import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.spec.InvalidKeySpecException

import javax.crypto.SecretKey

object PasswordEncryptor {
    private const val ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding"
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = KEY_LENGTH / 8

    //Delimiter should be used between components of the ciphertext
    // We chose '&' because is not part of the Base64 character set
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
    @Throws(GeneralSecurityException::class, IOException::class)
    fun decryptData(passphrase: String, input: InputStream): ByteArray? {
        /*
         * TODO: Encryption Lab:
         * Parse the ciphertext blob and unpack the stored iv, salt, and encrypted contents.
         * Construct and use a Cipher to decrypt the data.
         * Return the decrypted bytes.
         */
        return null
    }

    /**
     * Create a new symmetric key used in both encryption and decryption
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
    private fun generateSecretKey(passphraseOrPin: CharArray, salt: ByteArray): SecretKey? {
        /*
         * TODO: Encryption Lab:
         * Generate a new key from the supplied password+salt using AES.
         * Use KEY_LENGTH for the length of the generated key.
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
}
