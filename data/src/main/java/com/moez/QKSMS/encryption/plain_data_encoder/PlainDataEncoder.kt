package com.moez.QKSMS.encryption.plain_data_encoder

@ExperimentalUnsignedTypes
interface PlainDataEncoder {
    fun encode(s: String): UByteArray
    fun decode(data: UByteArray): String
    fun merge(data: UByteArray): UByteArray
    fun unMerge(data: UByteArray): UByteArray
    fun getMode(): Int
}