package com.moez.QKSMS.encryption.plain_data_encoder

@ExperimentalUnsignedTypes
class ShortCp1251Cyrillic : ShortEncoder() {
    override fun encodeChar(char: Char): Int {
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

    override fun decodeChar(code: UByte): Char {
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

    override fun getMode(): Int = Mode.CYRILLIC.ordinal

}