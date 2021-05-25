package com.moez.QKSMS.encryption.encrypted_data_encoder

interface EncryptedDataEncoder {
    fun encode(data: ByteArray): String
    fun decode(str: String): ByteArray
}