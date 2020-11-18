package com.moez.QKSMS.common.encryption

import java.math.BigInteger
import java.nio.charset.Charset
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.collections.ArrayList
import kotlin.collections.fold
import kotlin.collections.map
import kotlin.collections.plus
import kotlin.collections.reverse
import kotlin.collections.slice
import kotlin.collections.toByteArray
import kotlin.collections.toCharArray
import kotlin.collections.toList


const val SIGNATURE: Byte = 0b11000011.toByte()
const val IV = "jive2020jive2020"

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
            data.toList().fold(BigInteger.ZERO) {
                acc: BigInteger, x: UByte -> (acc shl 7) + x.toInt().toBigInteger()
            }.toByteArray().toUByteArray()
        } else {
            data
        }
        return merged + ubyteArrayOf(mode.ordinal.toUByte(), SIGNATURE.toUByte())
    }

    private fun unpack(data: UByteArray): Pair<UByteArray, EncryptionMode> {
        if (data.last() != SIGNATURE.toUByte())
            throw InvalidSignatureException()
        val mode = EncryptionMode.values()[data[data.size - 2].toInt()]
        val payload = data.slice(0..data.size - 3)
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
                { s: String -> s.map{ c -> encodeShortCp1251Latin(c).toUByte() }.toUByteArray() }
            EncryptionMode.CYRILLIC ->
                { s: String -> s.map{ c -> encodeShortCp1251Cyrillic(c).toUByte() }.toUByteArray() }
            EncryptionMode.CP1251 ->
                { s: String -> s.toByteArray(Charset.forName("Windows-1251")).toUByteArray() }
            else ->
                { s: String -> s.toByteArray().toUByteArray() }
        }
    }

    private fun makeDecodingStringConverter(mode: EncryptionMode): (UByteArray) -> String {
        return when (mode) {
            EncryptionMode.LATIN -> { data: UByteArray ->
                String(data.map{ x -> decodeShortCp1251Latin(x) }.toCharArray())
            }
            EncryptionMode.CYRILLIC -> { data: UByteArray ->
                String(data.map{ x -> decodeShortCp1251Cyrillic(x) }.toCharArray())
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

    private fun fixKey(key: String): String {
        return if (key.length < 16)
            key + " ".repeat(16 - key.length)
        else
            key.slice(0..15)
    }

    private fun encrypt(key: ByteArray, plainData: ByteArray): ByteArray? {
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(IV.toByteArray())
        val cipher: Cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plainData)
    }

    private fun decrypt(key: ByteArray, encryptedData: ByteArray): ByteArray {
        val keySpec = SecretKeySpec(key, "AES")
        val ivSpec = IvParameterSpec(IV.toByteArray())
        val cipher: Cipher = Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(encryptedData)
    }

    public fun encode(str: String, key: String, mode: EncryptionMode? = null): String {
        val realMode = mode ?: autoSelectMode(str)
        val encoded = makeEncodingStringConverter(realMode)(str)
        val binData = pack(encoded, realMode)
        val binKey = fixKey(key).toByteArray()
        val encryptedData = encrypt(binKey, binData.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedData)
    }

    public fun decode(str: String, key: String): String {
        val raw = Base64.getDecoder().decode(str)
        val binKey = fixKey(key).toByteArray()
        val decrypted = decrypt(binKey, raw)
        val (unpacked, mode) = unpack(decrypted.toUByteArray())
        return makeDecodingStringConverter(mode)(unpacked)
    }

    public fun tryDecode(str: String, key: String): String {
        return try {
            decode(str, key)
        } catch(e: Exception) {
            str
        }
    }
}