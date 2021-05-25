package com.moez.QKSMS.encryption.plain_data_encoder

import java.nio.charset.Charset

@ExperimentalUnsignedTypes
class Cp1251 : PlainDataEncoder {
    override fun encode(s: String): UByteArray {
        return s.toByteArray(Charset.forName("Windows-1251")).toUByteArray()
    }

    override fun decode(data: UByteArray): String {
        return String(data.toByteArray(), Charset.forName("Windows-1251"))
    }

    override fun merge(data: UByteArray): UByteArray = data
    override fun unMerge(data: UByteArray): UByteArray = data
    override fun getMode(): Int = Mode.CP1251.ordinal
}