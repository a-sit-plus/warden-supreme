import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.androidAttestationExtension
import at.asitplus.catchingUnwrapped
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.toKmpCertificate
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import com.android.keyattestation.verifier.KeyDescription
import com.google.android.attestation.ParsedAttestationRecord
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.DEROctetString
import java.io.ByteArrayInputStream
import java.security.cert.X509Certificate
import java.util.*
import kotlin.io.bufferedReader
import kotlin.io.forEachLine
import kotlin.use

val DebugStatementParserTest by testSuite {
    val json = Json { ignoreUnknownKeys = true }
    val classLoader = Thread.currentThread().contextClassLoader


    val proofs: List<List<String>> =
        catchingUnwrapped {
            classLoader.getResourceAsStream("DebugStatements.csv").bufferedReader(Charsets.UTF_8).use {

                val lst = mutableListOf<List<String>>()
                it.forEachLine { line ->

                    val parsed = json.parseToJsonElement(MultiBase.decode(line)!!.decodeToString()).jsonObject
                    lst += (parsed.getValue("genericAttestationProof").jsonArray).map { it.jsonPrimitive.content }

                }
                lst

            }
        }.getOrElse {
            emptyList()
        }

    if (proofs.isEmpty()) {
        if (System.getenv("NO_PRIVATE_TEST_DATA") != "true") throw RuntimeException("NO PRIVATE TEST DATA PRESENT. Fine for CI, but not for local tests")

        "No private test data present" {}
        return@testSuite
    }

    withData(proofs) - {
        val attestationCertChain =
            it.map {
                val certBytes = Base64.getUrlDecoder().decode(it)
                catchingUnwrapped {
                    certificateFactory.generateCertificate(
                        ByteArrayInputStream(
                            certBytes
                        )
                    ) as X509Certificate
                }.getOrNull()
            }.filterNotNull()

        if (attestationCertChain.isNotEmpty()) {


            val androidAttestationExtension = attestationCertChain.first().androidAttestationExtension
            "convert" - {
                withData(nameFn = { it.subjectX500Principal.toString() }, attestationCertChain) {
                    it.toKmpCertificate().isSuccess shouldBe true

                    var own = it.toKmpCertificate().getOrThrow()
                    if (!own.encodeToDer().contentEquals(it.encoded)) {
                        System.err.println("OWN: ${own.encodeToDer().toHexString()}")
                        System.err.println("ORI: ${it.encoded.toHexString()}")
                    }
                    own.encodeToDer() shouldBe it.encoded
                }
            }
            val fromGoogle =
                catchingUnwrapped { ParsedAttestationRecord.createParsedAttestationRecord(attestationCertChain) }.getOrNull()

            "Own" {
                if (fromGoogle == null) {
                    System.err.println("Old Google parser glitched out")
                    val newParser = catchingUnwrapped { KeyDescription.parseFrom(attestationCertChain.first()) }
                    return@invoke//well, well, well…}
                }
                androidAttestationExtension.shouldNotBeNull()
                catchingUnwrapped {

                    val reencoded = androidAttestationExtension.encodeToDer()
                    val original = (DEROctetString.fromByteArray(
                        attestationCertChain.first().getExtensionValue(
                            AttestationKeyDescription.oid.toString()
                        )
                    ) as ASN1OctetString).octets
                    if (!reencoded.contentEquals(original)) {
                        System.err.println("OWN: ${reencoded.toHexString()}")
                        System.err.println("ORI: ${original.toHexString()}")
                    }
                    reencoded shouldBe original

                }.getOrElse {
                    throw it
                }
                assertSemanticallyEqual(fromGoogle, androidAttestationExtension)


            }

        } else "Empty chain" {}
    }
}
