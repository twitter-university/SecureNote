
package com.example.android.securenote;

import android.app.Activity;
import android.app.DialogFragment;
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

public class GetPasswordDialog extends DialogFragment implements
        OnClickListener, TextWatcher {
    private static final String TAG = GetPasswordDialog.class.getSimpleName();

    public static final String VERIFY_PASSWORD_REQUEST_PARAM = "verifyPassword";
    public static final String MIN_PASSWORD_LENGTH_REQUEST_PARAM = "minPasswordLength";
    public static final String REQUEST_PARAM = "requestType";

    public static GetPasswordDialog newInstance(int requestType,
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
        public void onPasswordValid(int requestType, String password);

        public void onPasswordCancel();
    }

    private EditText mPassword;
    private EditText mPasswordVerification;
    private Button mOkButton;
    private int mMinPasswordLength;

    private OnPasswordListener mPasswordListener;

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        try {
            mPasswordListener = (OnPasswordListener) activity;
        } catch (ClassCastException e) {
            throw new IllegalArgumentException(
                    activity.getClass().getSimpleName()
                            + " shoud implement OnPasswordListener");
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        getDialog().setTitle(R.string.get_password_label);
        View content = inflater.inflate(R.layout.get_password, container, false);

        mPassword = content.findViewById(R.id.password_text);
        mPasswordVerification = content.findViewById(R.id.password_verification_text);
        mOkButton = content.findViewById(R.id.ok_button);

        content.findViewById(R.id.cancel_button).setOnClickListener(this);
        mOkButton.setOnClickListener(this);


        return content;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        final Bundle args = getArguments();

        boolean verifyPassword = args.getBoolean(VERIFY_PASSWORD_REQUEST_PARAM, true);
        if (verifyPassword) {
            mOkButton.setEnabled(false);
            mMinPasswordLength = args.getInt(MIN_PASSWORD_LENGTH_REQUEST_PARAM, 0);
            if (mMinPasswordLength > 0) {
                mPassword.setHint(super.getString(R.string.password_hint_min_length,
                        mMinPasswordLength));
            }
            mPassword.addTextChangedListener(this);
            mPasswordVerification.addTextChangedListener(this);
        } else {
            mPasswordVerification.setVisibility(View.GONE);
        }
    }

    @Override
    public void onPause() {
        super.onPause();
        mPassword.getText().clear();
        mPasswordVerification.getText().clear();
        Log.d(TAG, "Cleared password fields");
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.ok_button:
                final int requestType = getArguments().getInt(REQUEST_PARAM);
                final String password = mPassword.getText().toString();
                mPasswordListener.onPasswordValid(requestType, password);
                break;
            case R.id.cancel_button:
                mPasswordListener.onPasswordCancel();
                break;
            default:
                throw new IllegalArgumentException("Invalid Button");
        }
        // the passwords will be cleared during onPause()
        dismiss();
    }

    public void afterTextChanged(Editable s) {
        if (mPassword.length() < mMinPasswordLength) {
            Log.d(TAG, "Password too short");
            mOkButton.setEnabled(false);
        } else if (mPassword.length() != mPasswordVerification.length()) {
            Log.d(TAG, "Passwords' length differs");
            mOkButton.setEnabled(false);
        } else {
            for (int i = 0; i < mPassword.getText().length(); i++) {
                if (mPassword.getText().charAt(i) != mPasswordVerification.getText()
                        .charAt(i)) {
                    Log.d(TAG, "Passwords differ");
                    mOkButton.setEnabled(false);
                    return;
                }
            }
            Log.d(TAG, "Passwords are the same");
            mOkButton.setEnabled(true);
        }
    }

    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        // ignored
    }

    public void onTextChanged(CharSequence s, int start, int before, int count) {
        // ignored
    }
}
