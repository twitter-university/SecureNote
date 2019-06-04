
package com.example.android.securenote;

import android.annotation.SuppressLint;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.example.android.securenote.crypto.PasswordEncryptor;
import com.example.android.securenote.crypto.RSAHardwareEncryptor;

import java.io.InputStream;
import java.io.OutputStream;

public class SecureNoteActivity extends AppCompatActivity implements
        OnClickListener, TextWatcher, GetPasswordDialog.OnPasswordListener {
    private static final String TAG = SecureNoteActivity.class.getSimpleName();

    private static final String FILENAME = "secure.note";

    /* Password Activity Actions */
    private static final int GET_PASSWORD_FOR_LOAD = 1;
    private static final int GET_PASSWORD_FOR_SAVE = 2;

    private EditText noteText;
    private TextView resultText;
    private RadioGroup encryptionSelect;
    private Button saveButton;

    private PasswordEncryptor passwordEncryptor;
    private RSAHardwareEncryptor hardwareEncryptor;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.secure_note);

        noteText = findViewById(R.id.note_text);
        resultText = findViewById(R.id.text_result);
        encryptionSelect = findViewById(R.id.type_select);
        saveButton = findViewById(R.id.save_button);

        findViewById(R.id.load_button).setOnClickListener(this);
        saveButton.setOnClickListener(this);
        noteText.addTextChangedListener(this);
        noteText.setText(null);

        passwordEncryptor = new PasswordEncryptor();
        hardwareEncryptor = new RSAHardwareEncryptor(this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.secure_note, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        menu.findItem(R.id.delete_button)
                .setEnabled(this.isSecureNoteFilePresent());
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.delete_button:
                new AlertDialog.Builder(this)
                        .setMessage(R.string.delete_alert)
                        .setCancelable(false)
                        .setPositiveButton(android.R.string.yes,
                                new DialogInterface.OnClickListener() {
                                    public void onClick(DialogInterface dialog, int id) {
                                        deleteSecureNote();
                                    }
                                })
                        .setNegativeButton(android.R.string.no, null)
                        .show();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void getPassword(int requestCode, boolean verifyPasswords) {
        Log.d(TAG, "Getting password");
        GetPasswordDialog dialog = GetPasswordDialog.newInstance(requestCode,
                6, verifyPasswords);
        dialog.show(getSupportFragmentManager(),
                GetPasswordDialog.class.getSimpleName());
    }

    private boolean isSecureNoteFilePresent() {
        return getFileStreamPath(FILENAME).exists();
    }

    @Override
    public void onPasswordValid(int requestType, String password) {
        switch (requestType) {
            case GET_PASSWORD_FOR_LOAD:
                this.loadSecureNote(password);
                break;
            case GET_PASSWORD_FOR_SAVE:
                this.saveSecureNote(password);
                break;
        }
    }

    @Override
    public void onPasswordCancel() {
        Log.d(TAG, "Canceled result. Ignoring.");
    }

    public void onClick(View v) {
        int encryptionType = encryptionSelect.getCheckedRadioButtonId();
        switch (v.getId()) {
            case R.id.load_button:
                if (encryptionType == R.id.type_password) {
                    getPassword(GET_PASSWORD_FOR_LOAD, false);
                } else {
                    loadSecureNote(null);
                }
                break;
            case R.id.save_button:
                if (encryptionType == R.id.type_password) {
                    getPassword(GET_PASSWORD_FOR_SAVE, true);
                } else {
                    saveSecureNote(null);
                }
                break;
            default:
                throw new IllegalArgumentException("Invalid Button");
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        noteText.getText().clear();
    }

    private void deleteSecureNote() {
        Log.d(TAG, "Deleting note");
        if (super.getFileStreamPath(FILENAME).delete()) {
            toast(R.string.deleted_note);
            Log.d(TAG, "Deleted note");
        } else {
            toast(R.string.failed_to_delete);
            Log.e(TAG, "Failed to delete note");
        }
    }

    @SuppressLint("StaticFieldLeak")
    private void saveSecureNote(final String passkey) {
        Log.d(TAG, "Saving note");
        new AsyncTask<String, Void, Boolean>() {
            @Override
            protected Boolean doInBackground(String... strings) {
                try {
                    OutputStream out = openFileOutput(FILENAME, MODE_PRIVATE);
                    byte[] noteData = strings[0].getBytes();
                    if (passkey == null) {
                        hardwareEncryptor.encryptData(noteData, out);
                    } else {
                        passwordEncryptor.encryptData(passkey, noteData, out);
                    }
                    Log.d(TAG, "Saved note to " + FILENAME);

                    return true;
                } catch (Exception e) {
                    Log.e(TAG, "Failed to save note to " + FILENAME, e);
                    getFileStreamPath(FILENAME).delete();
                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean result) {
                if (result) {
                    noteText.getText().clear();
                    toast(R.string.saved_note);
                } else {
                    toast(R.string.failed_to_save);
                }
            }

        }.execute(noteText.getText().toString());
    }

    @SuppressLint("StaticFieldLeak")
    private void loadSecureNote(final String passkey) {
        Log.d(TAG, "Loading note...");
        new AsyncTask<Void, Void, String>() {
            @Override
            protected String doInBackground(Void... params) {
                try {
                    InputStream in = openFileInput(FILENAME);
                    byte[] decrypted;
                    if (passkey == null) {
                        decrypted = hardwareEncryptor.decryptData(in);
                    } else {
                        decrypted = passwordEncryptor.decryptData(passkey, in);
                    }
                    Log.d(TAG, "Loaded note from " + FILENAME);
                    return new String(decrypted);
                } catch (Exception e) {
                    Log.e(TAG, "Failed to load note from " + FILENAME, e);
                    return null;
                }
            }

            @Override
            protected void onPostExecute(String result) {
                if (result == null) {
                    toast(R.string.failed_to_load);
                } else {
                    resultText.setText(result);
                    toast(R.string.loaded_note);
                }
            }
        }.execute();
    }

    private void toast(int resId) {
        Toast.makeText(this, resId, Toast.LENGTH_LONG).show();
    }

    public void afterTextChanged(Editable s) {
        saveButton.setEnabled(s.length() != 0);
    }

    @Override
    public void beforeTextChanged(CharSequence s,
                                  int start,
                                  int count,
                                  int after) {
    }

    @Override
    public void onTextChanged(CharSequence s,
                              int start,
                              int before,
                              int count) {
    }
}
