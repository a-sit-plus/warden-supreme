import at.asitplus.attestation.supreme.Primitive
import at.asitplus.attestation.supreme.PrimitiveType
import at.asitplus.testballoon.matrix.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random

private fun Random.valueFor(type: PrimitiveType): Primitive = when (type) {
    PrimitiveType.NULL -> null
    PrimitiveType.BOOLEAN -> nextBoolean()
    PrimitiveType.STRING -> buildString {
        repeat(nextInt(65)) { append(nextInt(0x20, 0x7f).toChar()) }
    }
    PrimitiveType.BYTE -> nextInt(Byte.MIN_VALUE.toInt(), Byte.MAX_VALUE.toInt() + 1).toByte()
    PrimitiveType.SHORT -> nextInt(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt() + 1).toShort()
    PrimitiveType.INT -> nextInt()
    PrimitiveType.LONG -> nextLong()
    PrimitiveType.CHAR -> nextInt(Char.MIN_VALUE.code, Char.MAX_VALUE.code + 1).toChar()
    PrimitiveType.FLOAT -> nextInt(-1_000_000, 1_000_001) / 16f
    PrimitiveType.DOUBLE -> nextLong(-1_000_000, 1_000_001) / 16.0
    PrimitiveType.BYTEARRAY -> nextBytes(nextInt(65))
}

val PrimitiveTypeAsn1Test by matrixSuite {
    data("primitive types", PrimitiveType.entries, nameFn = { _, type -> type.name }) test { type ->
        val random = Random(type.id)

        repeat(100) { iteration ->
            val expected = if (iteration % 4 == 0) null else random.valueFor(type)
            val actual = type.asn1Decoder(type.asn1Encoder(expected))

            if (expected is ByteArray) {
                actual.shouldBeInstanceOf<ByteArray>().contentEquals(expected) shouldBe true
            } else {
                actual shouldBe expected
            }
        }
    }
}
