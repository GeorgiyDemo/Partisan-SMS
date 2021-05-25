package com.moez.QKSMS.encryption.encrypted_data_encoder

class CyrillicBase64 : EncryptedDataEncoder {
    private val cyrillic = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    private val latin = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    override fun encode(data: ByteArray): String {
        val base64 = Base64().encode(data)
        return String(base64.map { c -> cyrillic[latin.indexOf(c)] }.toCharArray())
    }

    override fun decode(str: String): ByteArray {
        val base64 = String(str.map { c -> latin[cyrillic.indexOf(c)] }.toCharArray())
        return Base64().decode(base64)
    }
}