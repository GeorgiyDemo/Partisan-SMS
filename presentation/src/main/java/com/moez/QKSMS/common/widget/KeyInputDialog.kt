package com.moez.QKSMS.common.widget

import android.app.Activity
import android.content.DialogInterface
import android.util.Base64
import android.view.LayoutInflater
import androidx.appcompat.app.AlertDialog
import com.moez.QKSMS.R
import kotlinx.android.synthetic.main.text_input_dialog.view.*
import javax.crypto.KeyGenerator

class KeyInputDialog(context: Activity, hint: String, val listener: (String) -> Unit) : AlertDialog(context) {

    private val layout = LayoutInflater.from(context).inflate(R.layout.text_input_dialog, null)

    init {
        layout.field.hint = hint

        setView(layout)
        setButton(DialogInterface.BUTTON_NEGATIVE, context.getString(R.string.button_cancel)) { _, _ -> }
        setButton(DialogInterface.BUTTON_NEUTRAL, context.getString(R.string.button_generate)) { _, _ -> }
        setButton(DialogInterface.BUTTON_POSITIVE, context.getString(R.string.button_save)) { _, _ -> }
    }

    fun setText(text: String): KeyInputDialog {
        if (validate(text)) {
            layout.field.setText(text)
        } else {
            layout.field.setText(text)
            layout.field.error = context.resources.getString(R.string.invalid_key)
        }
        return this
    }

    private fun validate(text: String): Boolean {
        return try {
            if (text.isEmpty()) {
                return true
            }
            val data = Base64.decode(text, Base64.DEFAULT)
            data.size == 16 || data.size == 24 || data.size == 32
        } catch (ignored: IllegalArgumentException) {
            false
        }
    }

    override fun show() {
        super.show()
        getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
            if (validate(layout.field.text.toString())) {
                listener(layout.field.text.toString())
                dismiss()
            } else {
                layout.field.error = context.resources.getString(R.string.invalid_key)
            }
        }
        getButton(DialogInterface.BUTTON_NEUTRAL).setOnClickListener {
            val keyGen = KeyGenerator.getInstance("AES")
            keyGen.init(256)
            val secretKey = keyGen.generateKey()
            layout.field.setText(Base64.encodeToString(secretKey.encoded, Base64.NO_WRAP))
        }
    }
}