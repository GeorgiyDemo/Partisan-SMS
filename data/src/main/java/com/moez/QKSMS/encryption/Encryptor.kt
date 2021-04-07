package com.moez.QKSMS.encryption

import java.math.BigInteger
import java.nio.charset.Charset
import java.security.MessageDigest
import java.util.*
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.collections.ArrayList

const val HASH_SIZE = 2;

@ExperimentalUnsignedTypes
class Encryptor {

    private fun encodeShortCp1251Latin(char: Char): Int {
        return when(char.toLowerCase().toInt()) {
            in 0x20..0x7E -> char.toInt()
            in 'a'.toInt()..'я'.toInt() -> char.toLowerCase().toInt() - 'a'.toInt() // special chars
            'ё'.toInt() -> 0x7F // del
            else -> '?'.toInt()
        }
    }

    private fun decodeShortCp1251Latin(code: UByte): Char {
        return when (val byteCode = code.toByte()) {
            in 0x20..0x7E -> byteCode.toChar()
            in 0x00..0x20 -> (byteCode + 'a'.toInt()).toChar() // special chars
            0x7F.toByte() -> 'ё' // del
            else -> '?'
        }
    }

    private fun encodeShortCp1251Cyrillic(char: Char): Int {
        return when(char) {
            in 0x20.toChar()..0x7E.toChar() -> char.toLowerCase().toInt()
            in 'a'..'я' -> char.toInt() - 'a'.toInt() // special chars
            'ё' -> 0x7F // del
            in 'А'..'И' -> char.toInt() - 'А'.toInt() + 'A'.toInt() // A - I
            'Ё' -> 'J'.toInt()
            in 'К'..'Щ' -> char.toInt() - 'К'.toInt() + 'K'.toInt() // K - Z
            in 'Ъ'..'Ь', 'Й' -> char.toInt() - 'А'.toInt() // as lower
            'Э' -> '&'.toInt()
            'Ю' -> '^'.toInt()
            'Я' -> '~'.toInt()
            else -> '?'.toInt()
        }
    }

    private fun decodeShortCp1251Cyrillic(code: UByte): Char {
        val byteCode = code.toByte()
        return when(byteCode.toChar()) {
            in 0x00.toChar()..0x20.toChar() -> (byteCode + 'a'.toInt()).toChar() // special chars
            0x7F.toChar() -> 'ё' // del
            in 'A'..'I' -> (byteCode - 'A'.toInt() + 'А'.toInt()).toChar()
            'J' -> 'Ё'
            in 'K'..'Z' -> (byteCode - 'K'.toInt() + 'К'.toInt()).toChar()
            '&' -> 'Э'
            '^' -> 'Ю'
            '~' -> 'Я'
            in 0x00.toChar()..0x7E.toChar() -> byteCode.toChar()
            else -> '?'
        }
    }

    private fun pack(data: UByteArray, mode: EncryptionMode): UByteArray {
        val merged = if (mode == EncryptionMode.CYRILLIC || mode == EncryptionMode.LATIN) {
            data.toList().fold(BigInteger.ZERO) { acc: BigInteger, x: UByte -> (acc shl 7) + x.toInt().toBigInteger()
            }.toByteArray().toUByteArray()
        } else {
            data
        }
        val hash = md5(merged.toByteArray()).toUByteArray()
        return merged + ubyteArrayOf(mode.ordinal.toUByte()) + hash.slice(0 until HASH_SIZE)
    }

    private fun unpack(data: UByteArray): Pair<UByteArray, EncryptionMode> {
        val payload = data.slice(0 until data.size - HASH_SIZE - 1)
        val hash = md5(payload.toUByteArray().toByteArray()).toUByteArray()
        if (data.slice(data.size-HASH_SIZE until data.size) != hash.slice(0 until HASH_SIZE))
            throw InvalidSignatureException()
        val mode = EncryptionMode.values()[data[data.size - HASH_SIZE - 1].toInt()]
        return if (mode == EncryptionMode.CYRILLIC || mode == EncryptionMode.LATIN) {
            var number = BigInteger(payload.toUByteArray().toByteArray())
            val result = ArrayList<Byte>()
            while (number > BigInteger.ZERO) {
                result.add((number and 0x7F.toBigInteger()).toByte())
                number = number shr 7
            }
            result.reverse()
            Pair(result.toByteArray().toUByteArray(), mode)
        }
        else {
            Pair(payload.toUByteArray(), mode)
        }
    }

    private fun makeEncodingStringConverter(mode: EncryptionMode): (String) -> UByteArray {
        return when (mode) {
            EncryptionMode.LATIN ->
                { s: String -> s.map { c -> encodeShortCp1251Latin(c).toUByte() }.toUByteArray() }
            EncryptionMode.CYRILLIC ->
                { s: String -> s.map { c -> encodeShortCp1251Cyrillic(c).toUByte() }.toUByteArray() }
            EncryptionMode.CP1251 ->
                { s: String -> s.toByteArray(Charset.forName("Windows-1251")).toUByteArray() }
            else ->
                { s: String -> s.toByteArray().toUByteArray() }
        }
    }

    private fun makeDecodingStringConverter(mode: EncryptionMode): (UByteArray) -> String {
        return when (mode) {
            EncryptionMode.LATIN -> { data: UByteArray ->
                String(data.map { x -> decodeShortCp1251Latin(x) }.toCharArray())
            }
            EncryptionMode.CYRILLIC -> { data: UByteArray ->
                String(data.map { x -> decodeShortCp1251Cyrillic(x) }.toCharArray())
            }
            EncryptionMode.CP1251 -> { data: UByteArray ->
                String(data.toByteArray(), Charset.forName("Windows-1251"))
            }
            else -> { data: UByteArray ->
                String(data.toByteArray())
            }
        }
    }

    private fun autoSelectMode(s: String): EncryptionMode {
        for (mode in EncryptionMode.values()) {
            val encoded = makeEncodingStringConverter(mode)(s)
            val decoded = makeDecodingStringConverter(mode)(encoded)
            if (decoded == s) {
                return mode
            }
        }
        return EncryptionMode.UTF_8
    }

    private fun md5(arr: ByteArray): ByteArray {
        val digest: MessageDigest = MessageDigest.getInstance("MD5")
        digest.update(arr)
        return digest.digest()
    }

    private fun encrypt(key: ByteArray, plainData: ByteArray): ByteArray {
        val keySpec = SecretKeySpec(key, "AES")
        val ivSrc = ByteArray(4)
        Random().nextBytes(ivSrc)
        val iv = ivSrc + ivSrc + ivSrc + ivSrc
        val ivSpec = IvParameterSpec(iv)
        val cipher: Cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plainData) + ivSrc
    }

    private fun decrypt(key: ByteArray, encryptedData: ByteArray): ByteArray {
        val keySpec = SecretKeySpec(key, "AES")
        val payload = encryptedData.slice(0 until encryptedData.size - 4).toByteArray()
        val ivSrc = encryptedData.slice(encryptedData.size - 4 until encryptedData.size).toByteArray()
        val ivSpec = IvParameterSpec(ivSrc + ivSrc + ivSrc + ivSrc)
        val cipher: Cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(payload)
    }

    public fun encode(str: String, key: String, mode: EncryptionMode? = null): String {
        val realMode = mode ?: autoSelectMode(str)
        val encoded = makeEncodingStringConverter(realMode)(str)
        val binData = pack(encoded, realMode)
        val binKey = md5(key.toByteArray())
        val encryptedData = encrypt(binKey, binData.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedData)
    }

    public fun decode(str: String, key: String): String {
        val raw = Base64.getDecoder().decode(str)
        val binKey = md5(key.toByteArray())
        val decrypted = decrypt(binKey, raw)
        val (unpacked, mode) = unpack(decrypted.toUByteArray())
        return makeDecodingStringConverter(mode)(unpacked)
    }

    public fun isEncrypted(str: String, key: String): Boolean {
        return try {
            decode(str, key)
            true
        } catch (e: Exception) {
            false
        }
    }

    public fun tryDecode(str: String, key: String): String {
        return try {
            decode(str, key)
        } catch (e: Exception) {
            str
        }
    }
}