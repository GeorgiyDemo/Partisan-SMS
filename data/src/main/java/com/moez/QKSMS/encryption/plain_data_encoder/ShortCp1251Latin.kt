package com.moez.QKSMS.encryption.plain_data_encoder

@ExperimentalUnsignedTypes
class ShortCp1251Latin : ShortEncoder() {
    override fun encodeChar(char: Char): Int {
        return when(char.toLowerCase().toInt()) {
            in 0x20..0x7E -> char.toInt()
            in 'a'.toInt()..'я'.toInt() -> char.toLowerCase().toInt() - 'a'.toInt() // special chars
            'ё'.toInt() -> 0x7F // del
            else -> '?'.toInt()
        }
    }

    override fun decodeChar(code: UByte): Char {
        return when (val byteCode = code.toByte()) {
            in 0x20..0x7E -> byteCode.toChar()
            in 0x00..0x20 -> (byteCode + 'a'.toInt()).toChar() // special chars
            0x7F.toByte() -> 'ё' // del
            else -> '?'
        }
    }

    override fun getMode(): Int = Mode.LATIN.ordinal
}