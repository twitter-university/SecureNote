
package com.example.android.securenote;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.CharBuffer;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
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

public class SecureNoteActivity extends Activity implements
        OnClickListener, TextWatcher {
    private static final String TAG = SecureNoteActivity.class.getSimpleName();

    private static final String PASSWORD_KEY = "password";
    private static final String CHARSET = "UTF-8";
    private static final String FILENAME = "secure.note";

    /* Password Activity Actions */
    private static final int GET_PASSWORD_FOR_LOAD = 1;
    private static final int GET_PASSWORD_FOR_SAVE = 2;

    private EditText noteText;
    private TextView resultText;
    private RadioGroup encryptionSelect;
    private Button loadButton;
    private Button saveButton;

    private PasswordEncryptor passwordEncryptor;
    private RSAHardwareEncryptor hardwareEncryptor;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.secure_note);

        this.noteText = (EditText) findViewById(R.id.note_text);
        this.resultText = (TextView) findViewById(R.id.text_result);
        this.encryptionSelect = (RadioGroup) findViewById(R.id.type_select);
        this.loadButton = (Button) findViewById(R.id.load_button);
        this.saveButton = (Button) findViewById(R.id.save_button);

        this.loadButton.setOnClickListener(this);
        this.saveButton.setOnClickListener(this);
        this.noteText.addTextChangedListener(this);

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
                                }).setNegativeButton(android.R.string.no, null).show();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void getPassword(int requestCode, boolean verifyPasswords) {
        Log.d(TAG, "Getting password");
        Intent intent = new Intent(this, GetPasswordActivity.class);
        intent.putExtra(GetPasswordActivity.MIN_PASSWORD_LENGTH_REQUEST_PARAM, 6);
        intent.putExtra(GetPasswordActivity.VERIFY_PASSWORD_REQUEST_PARAM, verifyPasswords);

        startActivityForResult(intent, requestCode);
    }

    private boolean isSecureNoteFilePresent() {
        return getFileStreamPath(FILENAME).exists();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        switch (resultCode) {
            case RESULT_OK:
                String passkey = data.getStringExtra(
                        GetPasswordActivity.PASSWORD_RESPONSE_PARAM);
                switch (requestCode) {
                    case GET_PASSWORD_FOR_LOAD:
                        this.loadSecureNote(passkey);
                        break;
                    case GET_PASSWORD_FOR_SAVE:
                        this.saveSecureNote(passkey);
                        break;
                }
                break;
            case RESULT_CANCELED:
                Log.d(TAG, "Canceled result. Ignoring.");
                break;
            default:
                Log.w(TAG, "Unexpected result: " + resultCode);
        }
    }

    public void onClick(View v) {
        int encryptionType = this.encryptionSelect.getCheckedRadioButtonId();
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
        this.noteText.getText().clear();
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

    private void saveSecureNote(final String passkey) {
        Log.d(TAG, "Saving note");
        new AsyncTask<String, Void, Boolean>() {

            @Override
            protected Boolean doInBackground(String... strings) {
                try {
                    OutputStream out = openFileOutput(FILENAME, MODE_PRIVATE);
                    String note = strings[0];
                    if (passkey == null) {
                        hardwareEncryptor.encryptData(note.getBytes(), out);
                    } else {
                        passwordEncryptor.encryptData(passkey, note.getBytes(), out);
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
                    SecureNoteActivity.this.noteText.getText().clear();
                    toast(R.string.saved_note);
                } else {
                    toast(R.string.failed_to_save);
                }
            }

        }.execute(this.noteText.getText().toString());
    }

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
                    SecureNoteActivity.this.resultText.setText(result);
                    toast(R.string.loaded_note);
                }
            }
        }.execute();
    }

    private void toast(int resId) {
        Toast.makeText(this, resId, Toast.LENGTH_LONG).show();
    }

    public void afterTextChanged(Editable s) {
        this.saveButton.setEnabled(true);
    }

    @Override
    public void beforeTextChanged(CharSequence s,
                                  int start,
                                  int count,
                                  int after) { }

    @Override
    public void onTextChanged(CharSequence s,
                              int start,
                              int before,
                              int count) { }
}
