package com.moez.QKSMS.encryption.plain_data_encoder

object PlainDataEncoderFactory {
    @ExperimentalUnsignedTypes
    fun create(mode: Int) : PlainDataEncoder {
        return when (mode) {
            Mode.LATIN.ordinal -> ShortCp1251Latin()
            Mode.CYRILLIC.ordinal -> ShortCp1251Cyrillic()
            Mode.CP1251.ordinal -> Cp1251()
            else -> Utf8()
        }
    }

    @ExperimentalUnsignedTypes
    fun createBestEncoder(s: String) : PlainDataEncoder {
        for (mode in Mode.values()) {
            val encoder = create(mode.ordinal)
            val encoded = encoder.encode(s)
            val decoded = encoder.decode(encoded)
            if (decoded == s) {
                return encoder
            }
        }
        return Utf8()
    }
}