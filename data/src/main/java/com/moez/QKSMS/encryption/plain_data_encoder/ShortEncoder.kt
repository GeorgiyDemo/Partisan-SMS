package com.moez.QKSMS.encryption.plain_data_encoder

import java.math.BigInteger

@ExperimentalUnsignedTypes
abstract class ShortEncoder : PlainDataEncoder {
    override fun encode(s: String): UByteArray = s.map { c -> encodeChar(c).toUByte() }.toUByteArray()
    override fun decode(data: UByteArray): String = String(data.map { x -> decodeChar(x) }.toCharArray())

    override fun merge(data: UByteArray): UByteArray {
        return data.toList().fold(BigInteger.ZERO) { acc: BigInteger, x: UByte ->
            (acc shl 7) + x.toInt().toBigInteger()
        }.toByteArray().toUByteArray()
    }
    override fun unMerge(data: UByteArray): UByteArray {
        var number = BigInteger(data.toUByteArray().toByteArray())
        val result = ArrayList<Byte>()
        while (number > BigInteger.ZERO) {
            result.add((number and 0x7F.toBigInteger()).toByte())
            number = number shr 7
        }
        result.reverse()
        return result.toByteArray().toUByteArray()
    }

    abstract fun encodeChar(char: Char): Int
    abstract fun decodeChar(code: UByte): Char
}