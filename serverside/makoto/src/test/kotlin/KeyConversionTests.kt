import at.asitplus.attestation.decodeBase64ToArray
import at.asitplus.attestation.parseToPublicKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe

val KeyConversionTests by testSuite {

    "Given an X509-encoded key" - {
        val x509Key =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFT1XwEeF8NftY84GfnqTFBoxHNkdG7wZHcOkLKwT4W6333Jqmga1XkKySq/ApnslBPNZE1Os363SAv8X85ZIrQ==".decodeBase64ToArray()
        "it should be parsable" - {
            val parsedKey = x509Key.parseToPublicKey()
            "and encodable to ANSI X9.62" - {
                val ansiBytes = parsedKey.toCryptoPublicKey().getOrThrow().iosEncoded
                "and decodable" - {
                    val decoded = ansiBytes.parseToPublicKey()
                    "to match the original X5095-encoded key" {
                        decoded.encoded shouldBe x509Key
                    }
                }
            }
        }
    }
}