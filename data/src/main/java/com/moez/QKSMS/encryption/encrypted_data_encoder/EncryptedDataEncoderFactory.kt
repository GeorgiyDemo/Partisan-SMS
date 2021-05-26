package com.moez.QKSMS.encryption.encrypted_data_encoder

import com.moez.QKSMS.encryption.plain_data_encoder.*

object EncryptedDataEncoderFactory {
    fun create(schemeId: Int) : EncryptedDataEncoder {
        return when (schemeId) {
            Scheme.BASE64.ordinal -> Base64()
            Scheme.CYRILLIC_BASE64.ordinal -> CyrillicBase64()
            else -> Base64()
        }
    }
}