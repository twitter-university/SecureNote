package com.example.android.securenote

import android.content.Context
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.View.OnClickListener
import android.view.ViewGroup
import com.example.android.securenote.databinding.GetPasswordBinding


class GetPasswordDialog : androidx.fragment.app.DialogFragment(), OnClickListener, TextWatcher {
    private var minPasswordLength: Int = 0
    private var passwordListener: OnPasswordListener? = null
    private lateinit var getPasswordBinding: GetPasswordBinding

    interface OnPasswordListener {
        fun onPasswordValid(requestType: Int, password: String)

        fun onPasswordCancel()
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        try {
            passwordListener = context as OnPasswordListener
        } catch (e: ClassCastException) {
            throw IllegalArgumentException("Must implement OnPasswordListener")
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        dialog?.setTitle(R.string.get_password_label)
        getPasswordBinding = GetPasswordBinding.inflate(layoutInflater)

        getPasswordBinding.cancelButton.setOnClickListener(this)
        getPasswordBinding.okButton.setOnClickListener(this)

        return getPasswordBinding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val args = arguments ?: return

        val verifyPassword = args.getBoolean(VERIFY_PASSWORD_REQUEST_PARAM, true)
        if (verifyPassword) {
            getPasswordBinding.okButton.isEnabled = false
            minPasswordLength = args.getInt(MIN_PASSWORD_LENGTH_REQUEST_PARAM, 0)
            if (minPasswordLength > 0) {
                getPasswordBinding.passwordText.hint = super.getString(
                    R.string.password_hint_min_length,
                    minPasswordLength
                )
            }
            getPasswordBinding.passwordText.addTextChangedListener(this)
            getPasswordBinding.passwordVerificationText.addTextChangedListener(this)
        } else {
            getPasswordBinding.passwordVerificationText.visibility = View.GONE
        }
    }

    override fun onPause() {
        super.onPause()
        getPasswordBinding.passwordText.text.clear()
        getPasswordBinding.passwordVerificationText.text.clear()
        Log.d(TAG, "Cleared password fields")
    }

    override fun onClick(v: View) {
        when (v.id) {
            R.id.ok_button -> {
                val requestType = requireArguments().getInt(REQUEST_PARAM)
                val password = getPasswordBinding.passwordText.text.toString()
                passwordListener!!.onPasswordValid(requestType, password)
            }
            R.id.cancel_button -> passwordListener!!.onPasswordCancel()
            else -> throw IllegalArgumentException("Invalid Button")
        }
        // the passwords will be cleared during onPause()
        dismiss()
    }

    override fun afterTextChanged(s: Editable) {
        when {
            getPasswordBinding.passwordText.length() < minPasswordLength -> {
                Log.d(TAG, "Password too short")
                getPasswordBinding.okButton.isEnabled = false
            }
            getPasswordBinding.passwordText.length() !=
                    getPasswordBinding.passwordVerificationText.length() -> {
                Log.d(TAG, "Passwords' length differs")
                getPasswordBinding.okButton.isEnabled = false
            }
            else -> {
                for (i in getPasswordBinding.passwordText.text.indices) {
                    if (getPasswordBinding.passwordText.text[i] !=
                        getPasswordBinding.passwordVerificationText.text[i]
                    ) {
                        Log.d(TAG, "Passwords differ")
                        getPasswordBinding.okButton.isEnabled = false
                        return
                    }
                }
                Log.d(TAG, "Passwords are the same")
                getPasswordBinding.okButton.isEnabled = true
            }
        }
    }

    override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {
        // ignored
    }

    override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {
        // ignored
    }

    companion object {
        private val TAG = GetPasswordDialog::class.java.simpleName

        const val VERIFY_PASSWORD_REQUEST_PARAM = "verifyPassword"
        const val MIN_PASSWORD_LENGTH_REQUEST_PARAM = "minPasswordLength"
        const val REQUEST_PARAM = "requestType"

        fun newInstance(
            requestType: Int,
            minPasswordLength: Int,
            verifyPassword: Boolean
        ): GetPasswordDialog {
            val dialog = GetPasswordDialog()
            val args = Bundle()
            args.putBoolean(VERIFY_PASSWORD_REQUEST_PARAM, verifyPassword)
            args.putInt(MIN_PASSWORD_LENGTH_REQUEST_PARAM, minPasswordLength)
            args.putInt(REQUEST_PARAM, requestType)
            dialog.arguments = args

            return dialog
        }
    }
}
