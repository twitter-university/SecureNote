package com.example.android.securenote

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.View.OnClickListener

import android.widget.Toast
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey

import com.example.android.securenote.crypto.PasswordEncryptor
import com.example.android.securenote.crypto.RSAHardwareEncryptor
import com.example.android.securenote.databinding.SecureNoteBinding
import kotlinx.coroutines.*
import java.io.File

class SecureNoteActivity : androidx.appcompat.app.AppCompatActivity(), OnClickListener, TextWatcher,
    GetPasswordDialog.OnPasswordListener {
    private lateinit var hardwareEncryptor: RSAHardwareEncryptor

    private val isSecureNoteFilePresent: Boolean get() = getFileStreamPath(FILENAME).exists()
    private lateinit var secureNoteBinding: SecureNoteBinding

    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        secureNoteBinding = SecureNoteBinding.inflate(layoutInflater)
        setContentView(secureNoteBinding.root)

        secureNoteBinding.loadButton.setOnClickListener(this)
        secureNoteBinding.saveButton.setOnClickListener(this)
        secureNoteBinding.noteText.addTextChangedListener(this)
        secureNoteBinding.noteText.text = null

        hardwareEncryptor = RSAHardwareEncryptor(this)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.secure_note, menu)
        return true
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        menu.findItem(R.id.delete_button).isEnabled = this.isSecureNoteFilePresent
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.delete_button -> {
                androidx.appcompat.app.AlertDialog.Builder(this)
                    .setMessage(R.string.delete_alert)
                    .setCancelable(false)
                    .setPositiveButton(
                        R.string.yes
                    ) { _, _ -> deleteSecureNote() }
                    .setNegativeButton(R.string.no, null)
                    .show()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun getEncryptedFile(autoDelete: Boolean = false): EncryptedFile {
        val file = File(filesDir, FILENAME)
        if (autoDelete && file.exists()) {
            file.delete()
        }

        return EncryptedFile.Builder(
            applicationContext.applicationContext,
            File(filesDir, FILENAME),
            MasterKey.Builder(applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build(),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
        ).build()
    }

    private fun getPassword(requestCode: Int, verifyPasswords: Boolean) {
        Log.d(TAG, "Getting password")
        val dialog = GetPasswordDialog.newInstance(
            requestCode,
            6, verifyPasswords
        )
        dialog.show(supportFragmentManager, GetPasswordDialog::class.java.simpleName)
    }

    override fun onPasswordValid(requestType: Int, password: String) {
        when (requestType) {
            GET_PASSWORD_FOR_LOAD -> this.loadSecureNote(password)
            GET_PASSWORD_FOR_SAVE -> this.saveSecureNote(password)
        }
    }

    override fun onPasswordCancel() {
        Log.d(TAG, "Canceled result. Ignoring.")
    }

    override fun onClick(v: View) {
        val encryptionType = secureNoteBinding.typeSelect.checkedRadioButtonId
        when (v.id) {
            R.id.load_button -> if (encryptionType == R.id.type_password) {
                getPassword(GET_PASSWORD_FOR_LOAD, false)
            } else {
                loadSecureNote(null)
            }
            R.id.save_button -> if (encryptionType == R.id.type_password) {
                getPassword(GET_PASSWORD_FOR_SAVE, true)
            } else {
                saveSecureNote(null)
            }
            else -> throw IllegalArgumentException("Invalid Button")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        secureNoteBinding.noteText.text.clear()
    }

    private fun deleteSecureNote() {
        Log.d(TAG, "Deleting note")
        if (super.getFileStreamPath(FILENAME).delete()) {
            toast(R.string.deleted_note)
            Log.d(TAG, "Deleted note")
        } else {
            toast(R.string.failed_to_delete)
            Log.e(TAG, "Failed to delete note")
        }
    }

    private fun saveSecureNote(passkey: String?) {
        Log.d(TAG, "Saving note")
        val noteData = secureNoteBinding.noteText.text.toString().toByteArray()
        CoroutineScope(Job()).launch(Dispatchers.IO) {
            try {
                if (passkey == null) {
                    hardwareEncryptor.encryptData(noteData, openFileOutput(FILENAME, Context.MODE_PRIVATE))
                } else {
                    PasswordEncryptor.encryptData(passkey, noteData,
                        getEncryptedFile(true).openFileOutput())
                }
                Log.d(TAG, "Saved note to $FILENAME")
                withContext(Dispatchers.Main) {
                    secureNoteBinding.noteText.text.clear()
                    toast(R.string.saved_note)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save note to $FILENAME", e)
                getFileStreamPath(FILENAME).delete()
                withContext(Dispatchers.Main) {
                    toast(R.string.failed_to_save)
                }
            }
        }
    }

    private fun loadSecureNote(passkey: String?) {
        Log.d(TAG, "Loading note...")
        CoroutineScope(Job()).launch(Dispatchers.IO) {
            try {
                val decrypted: ByteArray =
                    if (passkey == null) {
                        hardwareEncryptor.decryptData(openFileInput(FILENAME))
                    } else {
                        PasswordEncryptor.decryptData(passkey,
                            getEncryptedFile().openFileInput())
                    }
                Log.d(TAG, "Loaded note from $FILENAME")
                withContext(Dispatchers.Main) {
                    secureNoteBinding.textResult.text = String(decrypted)
                    toast(R.string.loaded_note)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load note from $FILENAME", e)
            }
        }
    }

    private fun toast(resId: Int) {
        Toast.makeText(this, resId, Toast.LENGTH_LONG).show()
    }

    override fun afterTextChanged(s: Editable) {
        secureNoteBinding.saveButton.isEnabled = s.isNotEmpty()
    }

    override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {
    }

    override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {
    }

    companion object {
        private val TAG = SecureNoteActivity::class.java.simpleName

        private const val FILENAME = "secure.note"

        /* Password Activity Actions */
        private const val GET_PASSWORD_FOR_LOAD = 1
        private const val GET_PASSWORD_FOR_SAVE = 2
    }
}
