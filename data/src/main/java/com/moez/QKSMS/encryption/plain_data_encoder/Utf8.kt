package com.moez.QKSMS.encryption.plain_data_encoder

@ExperimentalUnsignedTypes
class Utf8 : PlainDataEncoder {
    override fun encode(s: String): UByteArray = s.toByteArray().toUByteArray()
    override fun decode(data: UByteArray): String = String(data.toByteArray())
    override fun merge(data: UByteArray): UByteArray = data
    override fun unMerge(data: UByteArray): UByteArray = data
    override fun getMode(): Int = Mode.UTF_8.ordinal
}