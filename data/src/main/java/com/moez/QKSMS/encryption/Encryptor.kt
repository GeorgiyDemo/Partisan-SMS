package com.moez.QKSMS.encryption

import com.moez.QKSMS.encryption.plain_data_encoder.PlainDataEncoder
import com.moez.QKSMS.encryption.plain_data_encoder.PlainDataEncoderFactory
import java.math.BigInteger
import java.security.MessageDigest
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.collections.ArrayList

const val HASH_SIZE = 2;

@ExperimentalUnsignedTypes
class Encryptor {

    var plainDataEncoder: PlainDataEncoder? = null

    private fun pack(data: UByteArray): UByteArray {
        val merged = plainDataEncoder!!.merge(data)
        val hash = md5(merged.toByteArray()).toUByteArray()
        return merged + ubyteArrayOf(plainDataEncoder!!.getMode().toUByte()) + hash.slice(0 until HASH_SIZE)
    }

    private fun unpack(data: UByteArray): UByteArray {
        val payload = data.slice(0 until data.size - HASH_SIZE - 1)
        val hash = md5(payload.toUByteArray().toByteArray()).toUByteArray()
        if (data.slice(data.size-HASH_SIZE until data.size) != hash.slice(0 until HASH_SIZE))
            throw InvalidSignatureException()
        plainDataEncoder = PlainDataEncoderFactory.create(data[data.size - HASH_SIZE - 1].toInt())
        return plainDataEncoder!!.unMerge(payload.toUByteArray())
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

    public fun encode(str: String, key: String): String {
        plainDataEncoder = PlainDataEncoderFactory.createBestEncoder(str)
        val encoded = plainDataEncoder!!.encode(str)
        val binData = pack(encoded)
        val binKey = md5(key.toByteArray())
        val encryptedData = encrypt(binKey, binData.toByteArray())
        return Base64.getEncoder().encodeToString(encryptedData)
    }

    public fun decode(str: String, key: String): String {
        val raw = Base64.getDecoder().decode(str)
        val binKey = md5(key.toByteArray())
        val decrypted = decrypt(binKey, raw)
        val unpacked = unpack(decrypted.toUByteArray())
        return plainDataEncoder!!.decode(unpacked)
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