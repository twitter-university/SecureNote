
package com.example.android.securenote;

import android.app.Activity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;

import androidx.fragment.app.DialogFragment;

public class GetPasswordDialog extends DialogFragment implements
        OnClickListener, TextWatcher {
    private static final String TAG = GetPasswordDialog.class.getSimpleName();

    private static final String VERIFY_PASSWORD_REQUEST_PARAM = "verifyPassword";
    private static final String MIN_PASSWORD_LENGTH_REQUEST_PARAM = "minPasswordLength";
    private static final String REQUEST_PARAM = "requestType";

    static GetPasswordDialog newInstance(int requestType,
                                         int minPasswordLength,
                                         boolean verifyPassword) {
        GetPasswordDialog dialog = new GetPasswordDialog();
        Bundle args = new Bundle();
        args.putBoolean(VERIFY_PASSWORD_REQUEST_PARAM, verifyPassword);
        args.putInt(MIN_PASSWORD_LENGTH_REQUEST_PARAM, minPasswordLength);
        args.putInt(REQUEST_PARAM, requestType);
        dialog.setArguments(args);

        return dialog;
    }

    public interface OnPasswordListener {
        void onPasswordValid(int requestType, String password);

        void onPasswordCancel();
    }

    private EditText password;
    private EditText passwordVerification;
    private Button okButton;
    private int minPasswordLength;

    private OnPasswordListener passwordListener;

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            passwordListener = (OnPasswordListener) activity;
        } catch (ClassCastException e) {
            throw new IllegalArgumentException(
                    activity.getClass().getSimpleName()
                            + " should implement OnPasswordListener");
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        getDialog().setTitle(R.string.get_password_label);
        View content = inflater.inflate(R.layout.get_password, container, false);

        password = content.findViewById(R.id.password_text);
        passwordVerification = content.findViewById(R.id.password_verification_text);
        okButton = content.findViewById(R.id.ok_button);

        content.findViewById(R.id.cancel_button).setOnClickListener(this);
        okButton.setOnClickListener(this);


        return content;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        final Bundle args = getArguments();

        boolean verifyPassword = args.getBoolean(VERIFY_PASSWORD_REQUEST_PARAM, true);
        if (verifyPassword) {
            okButton.setEnabled(false);
            minPasswordLength = args.getInt(MIN_PASSWORD_LENGTH_REQUEST_PARAM, 0);
            if (minPasswordLength > 0) {
                password.setHint(super.getString(R.string.password_hint_min_length,
                        minPasswordLength));
            }
            password.addTextChangedListener(this);
            passwordVerification.addTextChangedListener(this);
        } else {
            passwordVerification.setVisibility(View.GONE);
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        password.getText().clear();
        passwordVerification.getText().clear();
        Log.d(TAG, "Cleared password fields");
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.ok_button:
                final int requestType = getArguments().getInt(REQUEST_PARAM);
                final String password = this.password.getText().toString();
                passwordListener.onPasswordValid(requestType, password);
                break;
            case R.id.cancel_button:
                passwordListener.onPasswordCancel();
                break;
            default:
                throw new IllegalArgumentException("Invalid Button");
        }
        // the passwords will be cleared during onPause()
        dismiss();
    }

    public void afterTextChanged(Editable s) {
        if (password.length() < minPasswordLength) {
            Log.d(TAG, "Password too short");
            okButton.setEnabled(false);
        } else if (password.length() != passwordVerification.length()) {
            Log.d(TAG, "Passwords' length differs");
            okButton.setEnabled(false);
        } else {
            for (int i = 0; i < password.getText().length(); i++) {
                if (password.getText().charAt(i) != passwordVerification.getText()
                        .charAt(i)) {
                    Log.d(TAG, "Passwords differ");
                    okButton.setEnabled(false);
                    return;
                }
            }
            Log.d(TAG, "Passwords are the same");
            okButton.setEnabled(true);
        }
    }

    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        // ignored
    }

    public void onTextChanged(CharSequence s, int start, int before, int count) {
        // ignored
    }
}
